//! The commands.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches};
use pk_cli_config::profile::{self, ProfileName, Profiles};
use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::private_file::{self, Replace};
use pk_cli_core::{dates, output, CliError, Paged, RangeArgs};
use pk_cli_documents::{Document, DownloadBatch, SavedDocument, SkippedDocument};
use pk_cli_selfupdate::Updater;
use pk_med_records::dto::{kind, method, relationship};
use pk_med_records::{create_export_file, Header, Organization, PatientContext, RecordsExport, Source, Trailer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::auth::{self, LoginSettings};
use crate::cli::*;
use crate::endpoints::{Endpoints, PORTAL};
use crate::fhir;
use crate::live::{self, Live};
use crate::pull::{self, Fetchable};
use crate::queries::Host;
use crate::session::{self, Key, Session, SessionStore};

/// What a run reads its sessions from, and whether it leaves the owner's
/// browser profiles alone: the binary's ([`Env::for_binary`]), or a test's
/// in-memory vault.
pub struct Env<'a> {
    pub sessions: &'a dyn Fn() -> Result<SessionStore, CliError>,
    pub hermetic: bool,
    /// Whether a command may ask at the terminal (a texted code, a
    /// confirmation). The tests run in process with no terminal to answer.
    pub prompts: bool,
    /// A stub's address for a new sign-in; `None` reads
    /// [`crate::endpoints::STUB_ENV`], and without it Salve's own hosts.
    pub stub: Option<String>,
}

impl Env<'static> {
    pub fn for_binary() -> Env<'static> {
        Env {
            sessions: &SessionStore::open,
            hermetic: session::hermetic(),
            prompts: true,
            stub: None,
        }
    }
}

impl Env<'_> {
    /// Where a new sign-in goes.
    pub fn endpoints(&self) -> Result<Endpoints, CliError> {
        match &self.stub {
            Some(base) => Endpoints::stub(base),
            None => Endpoints::from_env(),
        }
    }
}

const REPO: &str = "piekstra/salve-cli";
/// `info`'s profiles: health-records/v1 and documents/v1.
pub const PROFILES: &[&str] = &[pk_med_records::PROFILE, pk_cli_documents::PROFILE];
/// The organization's vendor: the app the clinics use.
const VENDOR: &str = "salve";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// The logins, one per Salve account (`salve profiles add <NAME>`),
    /// each with its clinic and label once signed in.
    #[serde(default, skip_serializing_if = "Profiles::is_empty")]
    pub profiles: Profiles,
}

/// Which flags came from the command line rather than the environment.
#[derive(Debug, Default, Clone, Copy)]
pub struct Given {
    pub profile_flag: bool,
}

impl Given {
    pub fn of(matches: &ArgMatches) -> Given {
        let mut m = Some(matches);
        let mut profile_flag = false;
        while let Some(level) = m {
            if level.try_get_raw("profile").ok().flatten().is_some()
                && level.value_source("profile") == Some(ValueSource::CommandLine)
            {
                profile_flag = true;
            }
            m = level.subcommand().map(|(_, sub)| sub);
        }
        Given { profile_flag }
    }
}

struct Ctx<'a> {
    cli: &'a Cli,
    given: Given,
    store: ConfigStore,
    env: &'a Env<'a>,
}

impl Ctx<'_> {
    fn json(&self) -> bool {
        self.cli.common.json
    }

    /// Whether to ask at the terminal: stdin is one, --json is off, and the
    /// caller allows it.
    fn interactive(&self) -> bool {
        self.env.prompts && self.cli.common.interactive()
    }

    fn note(&self, msg: &str) {
        if !self.cli.common.quiet {
            eprintln!("{msg}");
        }
    }

    fn config(&self) -> Result<Config, CliError> {
        self.store.load()
    }

    /// The profile a login command runs as (`--profile`, else
    /// `SALVE_PROFILE`): it must be configured; there is no default.
    fn profile(&self, cfg: &Config) -> Result<ProfileName, CliError> {
        profile::resolve(self.cli.profile.as_deref(), PROFILE_ENV, &cfg.profiles, BIN)
    }

    /// For a command that needs no sign-in: `--profile` on its command line
    /// is exit 2, and `SALVE_PROFILE` is not read.
    fn no_profile(&self, command: &str) -> Result<(), CliError> {
        if self.given.profile_flag {
            return Err(CliError::Usage(format!(
                "`{BIN} {command}` needs no sign-in and takes no --profile"
            )));
        }
        Ok(())
    }

    /// The profile, its settings and its stored session: exit 3 when it has
    /// not signed in.
    fn signed_in(&self) -> Result<(ProfileName, LoginSettings, Key, Session, SessionStore), CliError> {
        let cfg = self.config()?;
        let name = self.profile(&cfg)?;
        let settings: LoginSettings = cfg.profiles.settings(&name)?;
        let key = settings.key(&name).ok_or_else(|| session::not_signed_in(&name))?;
        let store = (self.env.sessions)()?;
        let session = store.load(&key)?;
        Ok((name, settings, key, session, store))
    }
}

pub fn main() {
    // A reader that closes the pipe early (`salve documents list | head`)
    // ends the process quietly, as it does any Unix tool.
    #[cfg(unix)]
    // SAFETY: called first, before any thread starts; it only resets the
    // disposition Rust's runtime set for SIGPIPE back to the default.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let given = Given::of(&matches);
    match run(&cli, given, &Env::for_binary()) {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(e) => std::process::exit(output::fail(&e, cli.common.json)),
    }
}

/// One command. `Ok` carries the exit code of a command that already wrote
/// its one document (an export that ended incomplete); `Err` is the error
/// to report.
pub fn run(cli: &Cli, given: Given, env: &Env) -> Result<i32, CliError> {
    let ctx = Ctx {
        cli,
        given,
        store: ConfigStore::new(BIN).with_override(cli.config.clone()),
        env,
    };
    if let Command::Records(RecordsCmd::Export(args)) = &cli.command {
        export_args(cli, args)?;
        return export(&ctx, args);
    }
    dispatch(&ctx).map(|()| 0)
}

fn dispatch(ctx: &Ctx) -> Result<(), CliError> {
    let cli = ctx.cli;
    match &cli.command {
        Command::Auth(AuthCmd::Reset { force }) => {
            ctx.no_profile("auth reset")?;
            auth::reset(*force, ctx.interactive(), ctx.env, ctx.json(), cli.common.quiet)
        }
        Command::Auth(cmd) => auth_cmd(ctx, cmd),
        Command::Profiles(cmd) => {
            ctx.no_profile("profiles")?;
            profiles_cmd(ctx, cmd)
        }
        Command::Orgs(cmd) => {
            ctx.no_profile("orgs")?;
            orgs_cmd(ctx, cmd)
        }
        Command::Patients(PatientsCmd::List) => patients(ctx),
        Command::Records(RecordsCmd::Export(_)) => unreachable!("run() handles records export"),
        Command::Documents(DocumentsCmd::List(range)) => {
            range.validate()?;
            documents_list(ctx, range)
        }
        Command::Documents(DocumentsCmd::Download(args)) => documents_download(ctx, args),
        Command::Api(args) => api(ctx, args),
        Command::SelfUpdate(args) => {
            ctx.no_profile("self-update")?;
            Updater {
                repo: REPO.into(),
                binary: BIN.into(),
                target: env!("BUILD_TARGET").into(),
                current: env!("CARGO_PKG_VERSION").into(),
            }
            .run(args, ctx.json(), cli.common.quiet)
        }
        Command::Completions { shell } => {
            ctx.no_profile("completions")?;
            clap_complete::generate(*shell, &mut Cli::command(), BIN, &mut std::io::stdout());
            Ok(())
        }
        Command::Info => {
            ctx.no_profile("info")?;
            let info = CliInfo::new(
                BIN,
                env!("CARGO_PKG_VERSION"),
                &format!("https://github.com/{REPO}"),
                AuthInfo {
                    required: true,
                    method: "password".into(),
                    login_hint: Some(format!(
                        "{BIN} auth login --profile <NAME> --op-item op://VAULT/ITEM (or --stdin, or --browser), then --code <CODE>"
                    )),
                },
                &[
                    "profiles",
                    "orgs",
                    "patients",
                    "records",
                    "documents",
                    "api",
                    pk_med_records::LOGIN_PROFILES,
                ],
            )
            .with_profiles(PROFILES);
            output::json(&serde_json::to_value(&info).expect("CliInfo serializes"));
            Ok(())
        }
    }
}

// ------------------------------------------------------------------ auth

fn auth_cmd(ctx: &Ctx, cmd: &AuthCmd) -> Result<(), CliError> {
    let quiet = ctx.cli.common.quiet;
    let cfg = ctx.config()?;
    let name = ctx.profile(&cfg)?;
    let settings: LoginSettings = cfg.profiles.settings(&name)?;
    match cmd {
        AuthCmd::Login(args) => {
            let done = auth::login(args, &name, &settings, ctx.env, ctx.interactive(), ctx.json(), quiet)?;
            // Reloaded: the sign-in may have taken minutes in a browser.
            let mut cfg = ctx.config()?;
            if cfg.profiles.contains(&name) {
                cfg.profiles.set_settings(&name, &done.settings)?;
                ctx.store.save(&cfg)?;
            }
            Ok(())
        }
        AuthCmd::Status { check } => auth::status(&name, &settings, *check, ctx.env, ctx.json(), quiet),
        AuthCmd::Logout => auth::logout(&name, &settings, ctx.env, ctx.json(), quiet),
        AuthCmd::Reset { .. } => unreachable!("run() handles auth reset"),
    }
}

// -------------------------------------------------------------- profiles

/// `profiles list|add|remove`: the logins, by name, in the config.
/// Removing one removes what salve keeps for it first.
fn profiles_cmd(ctx: &Ctx, cmd: &ProfilesCmd) -> Result<(), CliError> {
    match cmd {
        ProfilesCmd::List => {
            let cfg = ctx.config()?;
            let list = cfg.profiles.list();
            if ctx.json() {
                output::json(&serde_json::to_value(&list).unwrap_or_default());
            } else if list.profiles.is_empty() {
                ctx.note(&format!(
                    "no profiles: `{BIN} profiles add <NAME>`, one per Salve account"
                ));
            } else {
                for p in &list.profiles {
                    println!("{}", p.name);
                }
            }
            Ok(())
        }
        ProfilesCmd::Add { name } => {
            let name = ProfileName::parse(name)?;
            let mut cfg = ctx.config()?;
            let added = cfg.profiles.add(name.clone());
            if added {
                ctx.store.save(&cfg)?;
            }
            output::emit(
                ctx.json(),
                "profile-add",
                json!({ "profile": name.as_str(), "added": added }),
                |_| {
                    ctx.note(&if added {
                        format!("added profile {name}; sign in with `{BIN} auth login --profile {name} --op-item op://VAULT/ITEM`")
                    } else {
                        format!("profile {name} is already configured")
                    })
                },
            );
            Ok(())
        }
        ProfilesCmd::Remove { name, force } => {
            let name = ProfileName::parse(name)?;
            pk_cli_core::confirm::require_confirmable(*force, ctx.interactive(), "remove a profile")?;
            let cfg = ctx.config()?;
            if !cfg.profiles.contains(&name) {
                return Err(CliError::NotFound(format!("no profile `{name}`"))
                    .with_remedy(format!("`{BIN} profiles list` shows the configured ones")));
            }
            pk_cli_core::confirm::confirm(
                *force,
                &format!("Remove profile {name}, its stored sign-in and its browser profile?"),
            )?;
            let settings: LoginSettings = cfg.profiles.settings(&name)?;
            let done = auth::forget_login(&name, &settings, false, ctx.env)?;
            let mut cfg = ctx.config()?;
            cfg.profiles.remove(&name);
            ctx.store.save(&cfg)?;
            let mut v = json!({ "profile": name.as_str(), "session_removed": done.session_removed });
            if let Some(removed) = done.browser_profile_removed {
                v["browser_profile_removed"] = removed.into();
            }
            output::emit(ctx.json(), "profile-remove", v, |_| {
                ctx.note(&format!(
                    "removed profile {name}: {}",
                    if done.session_removed {
                        "its session was removed"
                    } else {
                        "no session was stored"
                    }
                ))
            });
            Ok(())
        }
    }
}

// ------------------------------------------------------------------ orgs

fn organization(clinic_id: &str, name: Option<&str>, stub: Option<&str>) -> Organization {
    Organization {
        id: clinic_id.to_string(),
        name: name.map(str::to_string).unwrap_or_else(|| clinic_id.to_string()),
        fhir_base: stub.unwrap_or(PORTAL).to_string(),
        vendor: Some(VENDOR.into()),
        location: None,
        aliases: Vec::new(),
    }
}

fn orgs_cmd(ctx: &Ctx, cmd: &OrgsCmd) -> Result<(), CliError> {
    let OrgsCmd::List = cmd;
    let cfg = ctx.config()?;
    let mut orgs: Vec<Organization> = Vec::new();
    for name in cfg.profiles.names() {
        let s: LoginSettings = cfg.profiles.settings(name)?;
        if let Some(id) = &s.clinic_id {
            if !orgs.iter().any(|o| &o.id == id) {
                orgs.push(organization(id, s.clinic.as_deref(), None));
            }
        }
    }
    if orgs.is_empty() && !ctx.json() {
        ctx.note(&format!(
            "no clinic yet: a profile's first `{BIN} auth login` adds its clinic"
        ));
        return Ok(());
    }
    if ctx.json() {
        pk_med_records::org_list(orgs).emit(true);
    } else {
        let rows: Vec<Value> = orgs.iter().map(|o| json!({ "id": o.id, "name": o.name })).collect();
        output::table(&rows);
    }
    Ok(())
}

// -------------------------------------------------------------- patients

fn patient_context(settings: &LoginSettings, key: &Key, s: &Session) -> PatientContext {
    PatientContext {
        id: s.patient_id.clone(),
        organization: s.clinic_id.clone(),
        label: settings.label.clone(),
        relationship: Some(relationship::SELF.into()),
        kind: Some(kind::PATIENT.into()),
        member_role: None,
        fhir_user: None,
        name: s.full_name.clone().or_else(|| match (&s.first_name, &s.last_name) {
            (Some(f), Some(l)) => Some(format!("{f} {l}")),
            _ => None,
        }),
        session: Some(key.to_string()),
    }
}

/// `patients list`: the profile's one patient, from the stored session. No
/// request.
fn patients(ctx: &Ctx) -> Result<(), CliError> {
    let (_, settings, key, s, _) = ctx.signed_in()?;
    let p = patient_context(&settings, &key, &s);
    if ctx.json() {
        pk_med_records::patient_list(vec![p]).emit(true);
    } else {
        output::table(&[json!({
            "label": p.label,
            "id": p.id,
            "organization": p.organization,
            "name": p.name,
        })]);
    }
    Ok(())
}

// ---------------------------------------------------------------- export

pub(crate) fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    dates::fmt_rfc3339(secs)
}

/// A date flag's value as `YYYY-MM-DD`, zero-padded so it compares as a
/// string. cli-common's `parse_iso` takes any day from 1 to 31, so a day the
/// month does not have is refused here.
fn iso(d: &str) -> Result<String, CliError> {
    let (y, m, day) = dates::parse_iso(d.trim())?;
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let last = match m {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > last {
        return Err(CliError::Usage(format!("`{}` is not a day of that month", d.trim())));
    }
    Ok(dates::fmt_iso((y, m, day)))
}

/// `records export`'s argument checks, before the config or the vault is
/// read.
fn export_args(cli: &Cli, args: &ExportArgs) -> Result<(), CliError> {
    if args.ndjson && cli.common.json {
        return Err(CliError::Usage("--ndjson is the output; drop --json".into()));
    }
    args.since.as_deref().map(iso).transpose()?;
    if !args.ndjson && args.output.is_none() {
        return Err(CliError::Usage(format!(
            "say where the records go: --ndjson for stdout (`| medrec import --from {BIN}`) or -o <DIR>"
        )));
    }
    Ok(())
}

fn incomplete_exit(trailer: &Trailer) -> i32 {
    trailer.error.as_ref().and_then(|e| e.exit_code).unwrap_or(1)
}

fn export(ctx: &Ctx, args: &ExportArgs) -> Result<i32, CliError> {
    let since = args.since.as_deref().map(iso).transpose()?;
    let (name, settings, key, s, store) = ctx.signed_in()?;
    let patient = patient_context(&settings, &key, &s);
    if let Some(want) = &args.patient {
        if want != &patient.id && Some(want) != patient.label.as_ref() {
            return Err(CliError::NotFound(format!(
                "profile `{name}` reads one patient, and `{want}` is neither its id nor its label (`{BIN} patients list`)"
            )));
        }
    }
    if args.output.is_some() && s.stub.is_none() {
        // A plain file of records is for synthetic data from the stub.
        return Err(CliError::Usage(
            "-o writes records to a plain file, so it is for the stub on this machine only".into(),
        )
        .with_remedy(format!(
            "pipe real records into medrec: `{BIN} records export --profile {name} --ndjson | medrec import --from {BIN}`"
        )));
    }
    let org = organization(
        &s.clinic_id,
        s.clinic_name.as_deref().or(settings.clinic.as_deref()),
        s.stub.as_deref(),
    );
    let pulled_at = now_rfc3339();
    let mut header = Header::new(
        Source::new(BIN, env!("CARGO_PKG_VERSION")),
        org.clone(),
        patient.clone(),
        &pulled_at,
    );
    header.method = Some(method::PORTAL.into());
    if let Some(day) = &since {
        header.since = Some(day.clone());
        header.since_unbounded = pull::SINCE_UNBOUNDED.iter().map(|t| t.to_string()).collect();
    }
    let fctx = fhir::Ctx {
        origin: org.fhir_base.clone(),
        patient: format!("Patient/{}", patient.id),
        clinic: org.name.clone(),
    };
    let who = pull::Who {
        patient_id: patient.id.clone(),
        full_name: s.full_name.clone(),
        first_name: s.first_name.clone(),
        last_name: s.last_name.clone(),
        birth_date: s.birth_date.clone(),
    };
    let now = pulled_at.clone();
    let clock = live::unix_now;
    let reader = Live::new(&store, key, s, &clock)?;

    if let Some(dir) = &args.output {
        let mut file = create_export_file(dir)?;
        let (finished, tally, err) =
            pull::export(&reader, std::io::BufWriter::new(&mut file), &header, &fctx, &who, &now)?;
        let path = file.commit(&finished)?;
        let summary = RecordsExport::new(path.display().to_string(), &finished);
        if ctx.json() {
            output::json(&serde_json::to_value(&summary).unwrap_or_default());
        } else {
            ctx.note(&format!(
                "wrote {} ({} resources{})",
                path.display(),
                finished.trailer.total(),
                since_note(tally.before_since)
            ));
        }
        if let Some(e) = err {
            eprintln!("error: {}", e.message());
            return Ok(incomplete_exit(&finished.trailer));
        }
        return Ok(0);
    }
    let stdout = std::io::stdout();
    let (finished, tally, err) = match pull::export(&reader, stdout.lock(), &header, &fctx, &who, &now) {
        Ok(done) => done,
        // stdout is the stream, so a write error goes to stderr only.
        Err(e) => {
            eprintln!("error: {}", e.message());
            return Ok(e.exit_code());
        }
    };
    if let Some(e) = err {
        // The trailer carries the error; no second document.
        eprintln!("error: {}", e.message());
        if let Some(r) = e.remedy() {
            eprintln!("  {r}");
        }
        return Ok(incomplete_exit(&finished.trailer));
    }
    ctx.note(&format!(
        "exported {} resources, {} skipped{}",
        finished.trailer.total(),
        finished.trailer.skipped.len(),
        since_note(tally.before_since)
    ));
    Ok(0)
}

fn since_note(n: u64) -> String {
    if n == 0 {
        String::new()
    } else {
        format!("; {n} dated before --since left out")
    }
}

// ------------------------------------------------------------- documents

fn document_of(f: &Fetchable) -> Document {
    let mut d = Document::new(f.id.clone(), f.name.clone());
    d.date = f.date.clone();
    d.category = Some(f.category.into());
    // The name `documents download` saves it under.
    d.file = Some(saved_name(f));
    d
}

fn documents_list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    let since = range.since.as_deref().map(iso).transpose()?;
    let until = range.until.as_deref().map(iso).transpose()?;
    let (_, _, key, s, store) = ctx.signed_in()?;
    let clock = live::unix_now;
    let (docs, missing) = pull::documents(&Live::new(&store, key, s, &clock)?)?;
    for m in &missing {
        eprintln!("warning: {m}");
    }
    let within = |d: &Option<String>| match d {
        None => since.is_none() && until.is_none(),
        Some(day) => since.as_ref().is_none_or(|s| day >= s) && until.as_ref().is_none_or(|u| day <= u),
    };
    let rows: Vec<Document> = docs
        .iter()
        .filter(|f| within(&f.date))
        .map(document_of)
        .take(range.limit.map(|n| n as usize).unwrap_or(usize::MAX))
        .collect();
    if !ctx.json() && rows.is_empty() {
        ctx.note("no documents");
        return Ok(());
    }
    if ctx.json() {
        Paged::new("document", rows).emit(true);
    } else {
        output::table(&document_rows(&rows));
    }
    Ok(())
}

/// `documents list`'s table: the same columns in the same order on every
/// row, a blank cell for an undated document. (cli-common's table takes its
/// columns from the rows in the order it first meets them.)
fn document_rows(rows: &[Document]) -> Vec<Value> {
    const COLUMNS: [&str; 5] = ["id", "date", "name", "category", "file"];
    rows.iter()
        .map(|d| {
            let v = serde_json::to_value(d).unwrap_or_default();
            Value::Object(
                COLUMNS
                    .iter()
                    .map(|c| (c.to_string(), v.get(*c).cloned().unwrap_or_else(|| Value::from(""))))
                    .collect(),
            )
        })
        .collect()
}

/// Whether `path` is a regular file (not a link) holding exactly `bytes`.
fn same_file(path: &Path, bytes: &[u8]) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.len() == bytes.len() as u64)
        && std::fs::read(path).is_ok_and(|b| b == bytes)
}

/// Write `bytes` to `path`, owner-only: an existing file only with
/// `overwrite`, replaced by rename so a failed write never leaves a partial
/// one.
fn write_private(path: &Path, bytes: &[u8], overwrite: bool) -> Result<(), CliError> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        return Err(CliError::Usage(format!("{} is a folder", path.display())));
    }
    let replace = if overwrite { Replace::Always } else { Replace::Never };
    private_file::write(path, bytes, replace).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::Usage(format!("{} exists; pass --overwrite to replace it", path.display()))
        } else {
            CliError::Other(format!("writing {}: {e}", path.display()))
        }
    })
}

/// A file name for a document: Salve's own, with anything a folder
/// path could read as structure (`/`, `\\`, `:`, a leading `.`, a control
/// character) replaced, its extension kept, at most 120 characters; the
/// document id when nothing is left.
fn saved_name(f: &Fetchable) -> String {
    let cleaned: String = f
        .name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || " -_.()+,&'".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_start_matches(['.', ' ']).to_string();
    let (stem, ext) = match cleaned.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= 8 => (stem.to_string(), Some(ext)),
        _ => (cleaned.clone(), None),
    };
    let stem: String = stem.chars().take(110).collect();
    let stem = stem.trim_end_matches(['.', ' ']).to_string();
    let stem = if stem.trim_matches(['_', '-', ' ']).is_empty() {
        f.id.clone()
    } else {
        stem
    };
    // A name with no extension takes the one its type has, so the file
    // opens in what reads that type.
    let ext = ext
        .map(str::to_string)
        .or_else(|| extension(&fhir::content_type(f.filetype.as_deref(), None, None)).map(str::to_string));
    match ext {
        Some(ext) => format!("{stem}.{ext}"),
        None => stem,
    }
}

/// The usual extension of a content type salve names.
fn extension(content_type: &str) -> Option<&'static str> {
    Some(match content_type {
        "application/pdf" => "pdf",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/tiff" => "tiff",
        "image/heic" => "heic",
        "text/plain" => "txt",
        "application/msword" => "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        _ => return None,
    })
}

fn documents_download(ctx: &Ctx, args: &DownloadArgs) -> Result<(), CliError> {
    if args.all && args.output.as_deref().is_some_and(|o| o.as_os_str() == "-") {
        return Err(CliError::Usage("--all writes a folder, not stdout".into()));
    }
    let (_, _, key, s, store) = ctx.signed_in()?;
    let clock = live::unix_now;
    let reader = Live::new(&store, key, s, &clock)?;
    let (docs, _) = pull::documents(&reader)?;
    if args.all {
        let dir = args.output.clone().unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir).map_err(|e| CliError::Other(format!("creating {}: {e}", dir.display())))?;
        let mut saved = Vec::new();
        let mut skipped = Vec::new();
        let mut used = std::collections::HashSet::new();
        for f in &docs {
            let doc = document_of(f);
            let bytes = match pull::fetch_checked(&reader, f) {
                Ok(b) => b,
                Err(e) if e.is_auth() => return Err(e),
                Err(e) => {
                    let code = if e.reason() == Some(pk_cli_core::Reason::BadRequest) {
                        pk_cli_documents::SKIP_VERIFY_FAILED
                    } else if e.exit_code() == 4 {
                        pk_cli_documents::SKIP_NO_FILE
                    } else {
                        pk_cli_documents::SKIP_UPSTREAM
                    };
                    skipped.push(SkippedDocument::new(doc.id.clone(), e.message().to_string()).with_code(code));
                    continue;
                }
            };
            // Salve's name, else one with the document id; a name taken
            // in this batch or by another file is passed over. A file there
            // already holding these bytes is this document, saved before.
            let plain = saved_name(f);
            let candidates = [plain.clone(), format!("{}_{plain}", f.id)];
            if let Some(name) = candidates
                .iter()
                .find(|name| !used.contains(&name.to_lowercase()) && same_file(&dir.join(name), &bytes))
            {
                used.insert(name.to_lowercase());
                skipped
                    .push(SkippedDocument::new(doc.id.clone(), format!("already saved as {name}")).with_code("exists"));
                continue;
            }
            let target = candidates.iter().find(|name| {
                !used.contains(&name.to_lowercase())
                    && (args.overwrite || std::fs::symlink_metadata(dir.join(name)).is_err())
            });
            let Some(name) = target else {
                skipped.push(
                    SkippedDocument::new(doc.id.clone(), "other files hold its names; --overwrite replaces them")
                        .with_code("name_taken"),
                );
                continue;
            };
            used.insert(name.to_lowercase());
            let path = dir.join(name);
            write_private(&path, &bytes, args.overwrite)?;
            saved.push(SavedDocument::from_document(
                &doc,
                path.display().to_string(),
                bytes.len() as u64,
            ));
        }
        let batch = DownloadBatch::new(dir.display().to_string(), saved).with_skipped(skipped);
        if ctx.json() {
            output::json(&serde_json::to_value(&batch).unwrap_or_default());
        } else {
            for s in &batch.skipped {
                ctx.note(&format!("skipped {}: {}", s.id, s.reason));
            }
            ctx.note(&format!(
                "saved {} document(s) to {}{}",
                batch.count,
                batch.dir,
                if batch.skipped.is_empty() {
                    String::new()
                } else {
                    format!("; {} skipped", batch.skipped.len())
                }
            ));
        }
        return Ok(());
    }
    let id = args.id.as_deref().expect("clap requires an id without --all").trim();
    let f = docs
        .iter()
        .find(|d| d.id == id)
        .ok_or_else(|| CliError::NotFound(format!("no document {id} (`{BIN} documents list`)")))?;
    let bytes = pull::fetch_checked(&reader, f)?;
    let doc = document_of(f);
    match args.output.as_deref() {
        Some(p) if p.as_os_str() == "-" => std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| CliError::Other(format!("writing stdout: {e}"))),
        other => {
            let path = match other {
                Some(p) if p.is_dir() => p.join(saved_name(f)),
                Some(p) => p.to_path_buf(),
                None => PathBuf::from(saved_name(f)),
            };
            write_private(&path, &bytes, args.overwrite)?;
            let saved = SavedDocument::from_document(&doc, path.display().to_string(), bytes.len() as u64);
            if ctx.json() {
                output::json(&serde_json::to_value(&saved).unwrap_or_default());
            } else {
                ctx.note(&format!("saved {} ({} bytes)", path.display(), bytes.len()));
            }
            Ok(())
        }
    }
}

// ------------------------------------------------------------------- api

/// `api <QUERY>`: one query, its answer printed as JSON. Files go through
/// `documents download`, which checks them.
fn api(ctx: &Ctx, args: &ApiArgs) -> Result<(), CliError> {
    crate::salve::check_read(&args.query)?;
    let variables = match &args.variables {
        None => json!({}),
        Some(text) => {
            let v: Value = serde_json::from_str(text)
                .map_err(|_| CliError::Usage("--variables is not JSON (it is not shown)".into()))?;
            if !v.is_object() {
                return Err(CliError::Usage("--variables is a JSON object".into()));
            }
            v
        }
    };
    let host = if args.patient_api { Host::Patient } else { Host::App };
    let (_, _, key, s, store) = ctx.signed_in()?;
    let clock = live::unix_now;
    let a = Live::new(&store, key, s, &clock)?.raw(host, &args.query, &variables)?;
    if ctx.json() {
        output::json(&json!({ "schema": "api-response/v1", "api": host.name(), "data": a.data, "errors": a.errors }));
    } else {
        println!("{}", serde_json::to_string_pretty(&a.data).unwrap_or_default());
        for e in &a.errors {
            eprintln!("warning: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_date_flag_is_a_real_day() {
        assert_eq!(iso("2024-02-29").unwrap(), "2024-02-29");
        assert_eq!(iso(" 2025-12-31 ").unwrap(), "2025-12-31");
        for bad in [
            "2025-02-29",
            "2025-02-30",
            "2025-04-31",
            "1900-02-29",
            "2025-13-01",
            "25-01-01",
        ] {
            assert_eq!(iso(bad).unwrap_err().exit_code(), 2, "{bad}");
        }
    }

    #[test]
    fn the_documents_table_keeps_its_columns_in_order() {
        let mut undated = Document::new("doc-1", "a.pdf");
        undated.file = Some("a.pdf".into());
        let mut dated = Document::new("att-2", "b.pdf");
        dated.date = Some("2025-01-02".into());
        let rows = document_rows(&[undated, dated]);
        for row in &rows {
            let keys: Vec<&String> = row.as_object().unwrap().keys().collect();
            assert_eq!(keys, ["id", "date", "name", "category", "file"]);
        }
        assert_eq!(rows[0]["date"], "");
        assert_eq!(rows[1]["date"], "2025-01-02");
    }

    fn parse(args: &[&str]) -> (Cli, Given) {
        let m = Cli::command().try_get_matches_from(args).unwrap();
        (Cli::from_arg_matches(&m).unwrap(), Given::of(&m))
    }

    #[test]
    fn a_profile_flag_is_seen_wherever_it_is_given() {
        assert!(parse(&["salve", "--profile", "adult1", "info"]).1.profile_flag);
        assert!(parse(&["salve", "info", "--profile", "adult1"]).1.profile_flag);
        assert!(!parse(&["salve", "info"]).1.profile_flag);
    }

    #[test]
    fn a_document_name_is_safe_for_a_folder() {
        let f = Fetchable {
            id: "doc-1".into(),
            name: "../Report 1.pdf".into(),
            category: "document",
            date: None,
            filetype: None,
            uri: "dummy".into(),
            conversation: None,
        };
        assert_eq!(saved_name(&f), "_Report 1.pdf");
        let plain = Fetchable {
            name: "Example consent.pdf".into(),
            ..f.clone()
        };
        assert_eq!(saved_name(&plain), "Example consent.pdf");
        let odd = Fetchable {
            name: "a\\b:c\u{7}.pdf".into(),
            ..f.clone()
        };
        assert_eq!(saved_name(&odd), "a_b_c_.pdf");
        let blank = Fetchable {
            name: "..".into(),
            ..f.clone()
        };
        assert_eq!(saved_name(&blank), "doc-1");
        let typed = Fetchable {
            name: "Treatment plan".into(),
            filetype: Some("pdf".into()),
            ..f
        };
        assert_eq!(saved_name(&typed), "Treatment plan.pdf");
        assert_eq!(document_of(&typed).file.as_deref(), Some("Treatment plan.pdf"));
    }
}
