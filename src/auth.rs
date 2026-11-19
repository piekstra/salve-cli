//! `auth login`, `auth status`, `auth logout`, `auth reset`, and what
//! `profiles remove` removes: a Salve sign-in per profile, kept through
//! [`SessionStore`].
//!
//! The sign-in proves the password to Cognito (SRP; it is never sent),
//! then Salve texts a code. At a terminal salve asks for it; otherwise the
//! waiting sign-in is parked in the vault and `auth login --code <CODE>`
//! finishes it, within about 3 minutes. What is kept is Cognito's tokens:
//! the refresh token renews the others without a password or a code until
//! it lapses or is revoked.
//!
//! A `--browser` sign-in runs Chrome in the profile's own kept browser
//! profile, where the person signs in and types the code on Salve's own
//! page, and reads the tokens that page keeps. In a hermetic run
//! ([`Env::hermetic`]), nothing touches the real browser profiles.

use pk_cli_auth::otp::{CodeSent, OtpCode, OtpLogin, OtpTransport, ParkingSlot};
use pk_cli_auth::{AuthLogin, AuthMethod, AuthStatus};
use pk_cli_browser::{BrowserError, Capture, HostRule, Launch};
use pk_cli_config::profile::ProfileName;
use pk_cli_core::{output, CliError, Reason};
use pk_cli_secrets::{OnePassword, OpRef, Secret};
use serde_json::{json, Value};

use crate::app::Env;
use crate::cli::{LoginCmd, BIN};
use crate::cognito::{Cognito, Step, Tokens};
use crate::endpoints::{Endpoints, CLIENT_ID};
use crate::live::Live;
use crate::model::{self, MeOnly, PatientAndClinic};
use crate::pull::Reader;
use crate::queries;
use crate::salve::{self, Api};
use crate::session::{self, Key, Session, SessionStore, KEYCHAIN_SERVICE_ENV};

/// Cognito keeps a sign-in waiting on its code about this long.
pub const CODE_WINDOW_SECS: u64 = 180;

/// What a profile's config says about its login.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginSettings {
    /// Salve's id for the clinic the account reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clinic_id: Option<String>,
    /// The clinic's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clinic: Option<String>,
    /// The household's label for the patient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl LoginSettings {
    /// The vault entry of the profile's sign-in, once it has signed in.
    pub fn key(&self, profile: &ProfileName) -> Option<Key> {
        Some(Key {
            profile: profile.clone(),
            org: org_segment(self.clinic_id.as_deref()?),
            patient: self.label.clone().unwrap_or_else(|| profile.to_string()),
        })
    }
}

/// A clinic id as one segment of a vault entry's name.
fn org_segment(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A label names a person in this household (`adult1`), never read from a
/// record: short, printable, no spaces.
pub fn check_label(label: &str) -> Result<(), CliError> {
    let ok =
        !label.is_empty() && label.len() <= 40 && label.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    if ok {
        Ok(())
    } else {
        Err(CliError::Usage(
            "a label is up to 40 letters, digits, `-`, `_` or `.` (`adult1`, `child1`)".into(),
        ))
    }
}

enum Source<'a> {
    Piped,
    OpItem(&'a str),
    Browser,
    /// `--code`: finish the parked sign-in.
    Code(OtpCode),
}

/// The sign-in's outcome, for the caller to store with the profile.
pub struct LoggedIn {
    pub settings: LoginSettings,
}

/// The texted code's half of the sign-in, for the shared one-time-code
/// flow: the waiting sign-in is Cognito's session handle and user id.
struct SmsTransport<'a> {
    cognito: &'a Cognito,
    endpoints: &'a Endpoints,
    waiting: Option<(Secret, String, Option<String>)>,
}

impl OtpTransport for SmsTransport<'_> {
    type Session = Tokens;

    fn request_code(&self) -> Result<CodeSent, CliError> {
        let (session, user_id, sent_to) = self
            .waiting
            .as_ref()
            .ok_or_else(|| CliError::Other("no sign-in is waiting on a code".into()))?;
        let mut sent = CodeSent::new(
            json!({ "session": session.expose(), "user_id": user_id, "stub": self.endpoints.stub }).to_string(),
        );
        sent.channel = Some("sms".into());
        sent.sent_to_hint = Some(sent_to.clone().unwrap_or_else(|| "the account's phone".into()));
        Ok(sent)
    }

    fn redeem(&self, in_flight: &str, code: &OtpCode) -> Result<Tokens, CliError> {
        let v: Value = serde_json::from_str(in_flight)
            .map_err(|_| CliError::Auth("the waiting sign-in is not one this salve parked".into()))?;
        if v["stub"].as_str() != self.endpoints.stub.as_deref() {
            return Err(CliError::Usage(
                "the waiting sign-in was started against other endpoints; start it again".into(),
            ));
        }
        let session = v["session"]
            .as_str()
            .ok_or_else(|| CliError::Auth("the waiting sign-in has no session".into()))?;
        let user_id = v["user_id"].as_str().unwrap_or_default();
        self.cognito.sms_code(&Secret::new(session), user_id, code.expose())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn login(
    cmd: &LoginCmd,
    profile: &ProfileName,
    stored: &LoginSettings,
    env: &Env,
    interactive: bool,
    json: bool,
    quiet: bool,
) -> Result<LoggedIn, CliError> {
    // Flags first: a refused combination reaches neither the keychain, nor
    // 1Password, nor Salve.
    let code = cmd.code.resolve()?;
    let piped = cmd.source.stdin || cmd.source.from_env.is_some();
    let source = match (code, piped, cmd.op_item.as_deref(), cmd.browser.browser) {
        (Some(code), false, None, false) => Source::Code(code),
        (Some(_), ..) => {
            return Err(CliError::Usage(
                "--code finishes a waiting sign-in on its own; it takes no other sign-in source".into(),
            ))
        }
        (None, true, None, false) => Source::Piped,
        (None, false, Some(item), false) => Source::OpItem(item),
        (None, false, None, true) => Source::Browser,
        (None, false, None, false) => {
            return Err(CliError::Usage(format!(
                "pass where the sign-in comes from: --stdin (the email, then the password, one per line), \
                 --from-env <VAR> (the same two lines), --op-item op://VAULT/ITEM (1Password), or --browser \
                 (Salve's own page); `{BIN} auth login --help`"
            )))
        }
        _ => {
            return Err(CliError::Usage(
                "pass one of --stdin, --from-env, --op-item and --browser".into(),
            ))
        }
    };
    if cmd.source.stdin && cmd.source.from_env.is_some() {
        return Err(CliError::Usage("pass one of --stdin and --from-env".into()));
    }
    let op_refs = match source {
        Source::OpItem(item) => Some(op_refs(item)?),
        _ => None,
    };
    if let Some(label) = &cmd.label {
        check_label(label)?;
    }
    let label = cmd
        .label
        .clone()
        .or_else(|| stored.label.clone())
        .unwrap_or_else(|| profile.to_string());
    check_label(&label)?;
    if stored.label.as_deref().is_some_and(|l| l != label) {
        return Err(CliError::Usage(format!(
            "profile `{profile}` keeps its sign-in as `{}`; `{BIN} auth logout --profile {profile}` first to \
             change the label",
            stored.label.as_deref().unwrap_or_default()
        )));
    }
    let endpoints = env.endpoints()?;

    let store = (env.sessions)()?;
    // Before anything is read or sent, so no sign-in is spent on one that
    // would not be stored. A `--code` finishes a sign-in that already
    // passed this check.
    if !matches!(source, Source::Code(_)) {
        if let Some(key) = stored.key(profile) {
            let previous = match store.get(&key) {
                Ok(found) => found,
                Err(e) if e.reason() == Some(Reason::CredentialUnreadable) => None,
                Err(e) => return Err(e),
            };
            if previous.is_some() && !cmd.overwrite {
                return Err(CliError::Usage(format!(
                    "a Salve sign-in is already stored for profile `{profile}`; pass --overwrite to sign in again \
                     (`{BIN} auth status --check --profile {profile}` says whether Salve still takes it)"
                )));
            }
        }
    }
    // Piped lines are read and checked before anything is sent.
    let piped_pair = match source {
        Source::Piped => Some(two_lines(&cmd.source.read(None)?)?),
        _ => None,
    };
    let cognito = Cognito::new(&endpoints)?;
    let slot = store.slot(profile);
    let finish_code =
        |waiting: Option<(Secret, String, Option<String>)>, code: Option<&OtpCode>| -> Result<Tokens, CliError> {
            let transport = SmsTransport {
                cognito: &cognito,
                endpoints: &endpoints,
                waiting,
            };
            OtpLogin::new(BIN, &transport, &slot)
                .interactive(interactive)
                .quiet(quiet)
                .max_age_secs(CODE_WINDOW_SECS)
                .login(code)
                .map_err(|e| {
                    let Some(parked) = slot.load().ok().flatten().filter(|_| e.is_auth()) else {
                        return e;
                    };
                    // The shared flow's message names the command without the
                    // profile; say it once, with it.
                    let message = if e.message().starts_with("a verification code was sent") {
                        format!(
                            "Salve texted a code to {}",
                            parked.sent_to_hint.as_deref().unwrap_or("the account's phone")
                        )
                    } else {
                        // A refused code's message ends with the retry
                        // command; the remedy below says it with the profile.
                        let m = e.message();
                        m.split_once("; retry with").map_or(m, |(said, _)| said).to_string()
                    };
                    CliError::Auth(message)
                        .because(e.reason().unwrap_or(Reason::CredentialRefused))
                        .with_remedy(format!(
                            "{BIN} auth login --profile {profile} --code <CODE>, within about 3 minutes of the text"
                        ))
                })
        };
    let now = crate::live::unix_now();
    let tokens = match source {
        Source::Code(code) => finish_code(None, Some(&code))?,
        Source::Piped | Source::OpItem(_) => {
            let (email, password) = match piped_pair {
                Some(pair) => pair,
                None => {
                    let (user_ref, password_ref) = op_refs.expect("parsed above");
                    let op = OnePassword::new();
                    (op.read(&user_ref)?, op.read(&password_ref)?)
                }
            };
            match cognito.sign_in(&email, &password, now)? {
                Step::Done(t) => t,
                Step::SmsCode {
                    session,
                    user_id,
                    sent_to,
                } => finish_code(Some((session, user_id, sent_to)), None)?,
            }
        }
        Source::Browser => browser_tokens(profile, &endpoints, cmd.browser.fresh_profile, env.hermetic, quiet)?,
    };
    let session = read_account(&endpoints, tokens, now)?;
    let settings = LoginSettings {
        clinic_id: Some(session.clinic_id.clone()),
        clinic: session.clinic_name.clone(),
        label: Some(label),
    };
    let key = settings.key(profile).expect("a clinic id is set");
    if let Some(old) = stored.key(profile).filter(|k| *k != key) {
        // The account now reads another clinic: the old entry goes.
        store.delete(&old)?;
    }
    store.put(&key, &session)?;
    if !quiet {
        eprintln!(
            "Salve sign-in stored for profile `{profile}` ({})",
            session.clinic_name.as_deref().unwrap_or("its clinic")
        );
    }
    if json {
        output::json(&AuthLogin::stored(true).to_json());
    }
    Ok(LoggedIn { settings })
}

/// What a new sign-in reads about the account: the patient and the clinic.
fn read_account(endpoints: &Endpoints, t: Tokens, now: u64) -> Result<Session, CliError> {
    let refresh = t
        .refresh_token
        .as_ref()
        .map(|r| Secret::new(r.expose()))
        .ok_or_else(|| CliError::Upstream("the sign-in answered no refresh token".into()))?;
    let api = Api::new(endpoints)?;
    let claims = session::claims(t.id_token.expose()).unwrap_or(Value::Null);
    let clinic_token = claims["custom:clinictoken"].as_str().map(str::to_string);
    let a = salve::op_query(
        &api,
        &queries::PATIENT_AND_CLINIC,
        &json!({}),
        &t.id_token,
        clinic_token.as_deref(),
    )?;
    let pc: PatientAndClinic = model::read(a.data, "the patient and clinic")?;
    let names = salve::op_query(
        &api,
        &queries::PATIENT_ID,
        &json!({}),
        &t.id_token,
        clinic_token.as_deref(),
    )
    .ok()
    .and_then(|a| model::read::<MeOnly>(a.data, "the patient").ok())
    .and_then(|m| m.me)
    .unwrap_or_default();
    let me = pc.me.unwrap_or_default();
    let clinic = pc.clinic.unwrap_or_default();
    let patient_id = me
        .patientid
        .or(names.patientid.clone())
        .ok_or_else(|| CliError::Upstream("Salve answered no patient id for the account".into()))?;
    let clinic_id = clinic
        .id
        .ok_or_else(|| CliError::Upstream("Salve answered no clinic for the account".into()))?;
    let claim = |k: &str| {
        claims[k]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Ok(Session {
        expires_at: session::expiry(&t, now),
        id_token: t.id_token,
        access_token: t.access_token,
        refresh_token: refresh,
        patient_id,
        full_name: me.name,
        first_name: names.firstname.or_else(|| claim("given_name")),
        last_name: names.lastname.or_else(|| claim("family_name")),
        birth_date: claim("birthdate"),
        clinic_id,
        clinic_name: clinic.name,
        stub: endpoints.stub.clone(),
        signed_in_at: crate::app::now_rfc3339(),
    })
}

/// The two 1Password references an item names: its `username` and
/// `password` fields. The input is not echoed in an error: it may be a
/// secret pasted where its reference belongs.
fn op_refs(item: &str) -> Result<(OpRef, OpRef), CliError> {
    let item = item.trim_end_matches('/');
    let segments = item.strip_prefix("op://").map(|r| r.split('/').count());
    let bad =
        || CliError::Usage("--op-item is a 1Password item, op://VAULT/ITEM (the value given is not shown)".into());
    if segments != Some(2) {
        return Err(bad());
    }
    let field = |name: &str| format!("{item}/{name}").parse::<OpRef>().map_err(|_| bad());
    Ok((field("username")?, field("password")?))
}

/// The email and the password, one per line. The error never quotes
/// either.
fn two_lines(raw: &Secret) -> Result<(Secret, Secret), CliError> {
    let text = raw.expose();
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let user = lines.next().unwrap_or_default().trim();
    let password = lines.next().unwrap_or_default();
    let rest_blank = lines.all(|l| l.trim().is_empty());
    if user.is_empty() || password.is_empty() || !rest_blank {
        return Err(CliError::Usage(
            "the sign-in reads two lines: the email, then the password (what was read is not shown)".into(),
        ));
    }
    Ok((Secret::new(user), Secret::new(password)))
}

/// Salve's web app keeps its Cognito tokens in local storage, as Amplify
/// does: under `CognitoIdentityServiceProvider.<client>.<user>.<token>`,
/// the user named by `...LastAuthUser`.
fn storage_expression() -> String {
    format!(
        "(() => {{ const p = 'CognitoIdentityServiceProvider.{CLIENT_ID}.'; \
         const u = localStorage.getItem(p + 'LastAuthUser'); if (!u) return null; \
         const g = (k) => localStorage.getItem(p + u + '.' + k); \
         const i = g('idToken'), a = g('accessToken'), r = g('refreshToken'); \
         if (!i || !a || !r) return null; return JSON.stringify({{ i: i, a: a, r: r }}); }})()"
    )
}

/// Tokens from a Chrome window: the person signs in on Salve's own page,
/// code included, and the capture reads the tokens once the page keeps
/// them.
fn browser_tokens(
    profile: &ProfileName,
    endpoints: &Endpoints,
    fresh: bool,
    hermetic: bool,
    quiet: bool,
) -> Result<Tokens, CliError> {
    let scratch = fresh || hermetic;
    if scratch && !fresh && !quiet {
        eprintln!(
            "{KEYCHAIN_SERVICE_ENV} is set, so this sign-in uses a fresh browser profile and leaves the kept one alone"
        );
    }
    let host = endpoints
        .portal
        .split_once("://")
        .map(|(_, h)| h.split([':', '/']).next().unwrap_or(h).to_string())
        .unwrap_or_default();
    let rule = HostRule::exact(&host).map_err(CliError::from)?;
    let capture = Capture::new("Salve sign-in", rule)
        .expression(storage_expression())
        .hint("sign in on Salve's page, code included; the window closes once Salve shows your home page");
    let launch = Launch::new(BIN)
        .url(format!("{}/login", endpoints.portal))
        .profile_name(profile.as_str())
        .fresh_profile(scratch)
        .login_hint(format!("{BIN} auth login --browser --profile {profile}"))
        .quiet(quiet);
    let captured = pk_cli_browser::capture(launch, &capture, pk_cli_browser::DEFAULT_TIMEOUT).map_err(|e| match e {
        e @ BrowserError::ChromeNotFound(_) => CliError::from(e).with_remedy(format!(
            "without Chrome, sign in with the password: `{BIN} auth login --op-item op://VAULT/ITEM --profile {profile}`"
        )),
        e => e.into(),
    })?;
    let raw = captured
        .into_value()
        .ok_or_else(|| CliError::Other("the sign-in window handed over no sign-in".into()))?;
    let v: Value = serde_json::from_str(raw.expose())
        .map_err(|_| CliError::Upstream("Salve's page keeps its sign-in in a shape salve does not read".into()))?;
    let get = |k: &str| v[k].as_str().filter(|s| !s.is_empty()).map(Secret::new);
    match (get("i"), get("a"), get("r")) {
        (Some(i), Some(a), Some(r)) => Ok(Tokens {
            id_token: i,
            access_token: a,
            refresh_token: Some(r),
            expires_in: 3600,
        }),
        _ => Err(CliError::Upstream(
            "Salve's page keeps its sign-in in a shape salve does not read".into(),
        )),
    }
}

// ---------------------------------------------------------------- status

/// `auth status`: local facts, and with `check` one read of Salve.
pub fn status(
    profile: &ProfileName,
    settings: &LoginSettings,
    check: bool,
    env: &Env,
    json: bool,
    quiet: bool,
) -> Result<(), CliError> {
    let store = match settings.key(profile) {
        None => None,
        Some(_) => Some((env.sessions)()?),
    };
    let (stored, session) = match (settings.key(profile), &store) {
        (Some(key), Some(store)) => match store.get(&key) {
            Ok(session) => (session.is_some(), session),
            Err(e) if e.reason() == Some(Reason::CredentialUnreadable) => {
                eprintln!("warning: {}", e.message());
                (true, None)
            }
            Err(e) => return Err(e),
        },
        _ => (false, None),
    };
    let signed_in_at = session.as_ref().map(|s| s.signed_in_at.clone());
    let clinic = session.as_ref().and_then(|s| s.clinic_name.clone());
    let valid = match (session, check, &store, settings.key(profile)) {
        (Some(s), true, Some(store), Some(key)) => {
            let now = crate::live::unix_now;
            let live = Live::new(store, key, s, &now)?;
            match live.query(&queries::PATIENT_ID, &json!({})) {
                Ok(_) => Some(true),
                Err(e) if e.is_auth() => Some(false),
                Err(e) => return Err(e),
            }
        }
        _ => None,
    };
    let mut status = AuthStatus::new(true, stored && valid != Some(false), AuthMethod::Password);
    status.account = Some(profile.as_str().to_string());
    status.credential_in_keychain = Some(stored);
    status.session_valid = valid;
    if env.hermetic {
        if !quiet {
            eprintln!("{KEYCHAIN_SERVICE_ENV} is set, so the kept browser profile is not reported");
        }
    } else {
        match pk_cli_browser::named_profile_exists(BIN, profile.as_str()) {
            Ok(kept) => status.browser_profile = Some(kept),
            Err(e) => eprintln!("warning: {e}"),
        }
    }
    if json {
        let mut v = status.to_json();
        if let Some(at) = &signed_in_at {
            v["signed_in_at"] = json!(at);
        }
        if let Some(c) = &clinic {
            v["clinic"] = json!(c);
        }
        output::json(&v);
    } else {
        status.render();
        if let Some(c) = &clinic {
            println!("Clinic:        {c}");
        }
        if let Some(at) = &signed_in_at {
            println!("Signed in:     {at}");
        }
        if valid == Some(false) && !quiet {
            eprintln!("Salve no longer takes the sign-in: `{BIN} auth login --overwrite --profile {profile} ...`");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- logout

/// What `auth logout` did (`auth-logout/v1`).
#[derive(Debug, PartialEq, Eq)]
pub struct LoggedOut {
    pub session_removed: bool,
    /// Whether Salve revoked the sign-in; `None` with none to revoke.
    pub revoked: Option<bool>,
    /// `None` when the browser profile was left alone ([`KEYCHAIN_SERVICE_ENV`]).
    pub browser_profile_removed: Option<bool>,
}

impl LoggedOut {
    pub fn to_json(&self) -> Value {
        let mut v = json!({ "schema": "auth-logout/v1", "session_removed": self.session_removed });
        if let Some(r) = self.revoked {
            v["revoked_at_salve"] = r.into();
        }
        if let Some(removed) = self.browser_profile_removed {
            v["browser_profile_removed"] = removed.into();
        }
        v
    }

    pub fn line(&self) -> String {
        let session = match (self.session_removed, self.revoked) {
            (true, Some(true)) => "revoked the sign-in at Salve and removed it from the vault",
            (true, Some(false)) => "removed the sign-in from the vault; Salve did not confirm revoking it",
            (true, None) => "removed the sign-in from the vault",
            (false, _) => "no sign-in was stored",
        };
        let profile = match self.browser_profile_removed {
            Some(true) => "the browser profile was removed".to_string(),
            Some(false) => "no browser profile was kept".to_string(),
            None => format!("{KEYCHAIN_SERVICE_ENV} is set, so the kept browser profile was left alone"),
        };
        format!("logged out: {session}; {profile}")
    }
}

pub fn logout(
    profile: &ProfileName,
    settings: &LoginSettings,
    env: &Env,
    json: bool,
    quiet: bool,
) -> Result<(), CliError> {
    let done = forget_login(profile, settings, true, env)?;
    if json {
        output::json(&done.to_json());
    } else if !quiet {
        eprintln!("{}", done.line());
    }
    Ok(())
}

/// What a login keeps, removed: the sign-in (revoked at Salve first when
/// `at_salve`, which a failure to reach it does not stop), any sign-in
/// waiting on a code, then the browser profile, which a hermetic run
/// leaves alone.
pub fn forget_login(
    profile: &ProfileName,
    settings: &LoginSettings,
    at_salve: bool,
    env: &Env,
) -> Result<LoggedOut, CliError> {
    let mut revoked = None;
    let mut removed = false;
    let store: Option<SessionStore> = match settings.key(profile) {
        Some(_) => Some((env.sessions)()?),
        None => None,
    };
    if let (Some(key), Some(store)) = (settings.key(profile), &store) {
        let session = match store.get(&key) {
            Ok(s) => s,
            Err(e) if e.reason() == Some(Reason::CredentialUnreadable) => None,
            Err(e) => return Err(e),
        };
        if let (Some(s), true) = (&session, at_salve) {
            let done = Endpoints::of_session(s.stub.as_deref())
                .and_then(|ep| Cognito::new(&ep))
                .and_then(|c| c.revoke(&s.refresh_token));
            if let Err(e) = &done {
                eprintln!("warning: Salve was not told: {}", e.message());
            }
            revoked = Some(done.is_ok());
        }
        removed = store.delete(&key)?;
        store.slot(profile).clear()?;
    }
    let browser = if env.hermetic {
        None
    } else {
        Some(pk_cli_browser::forget_named_profile(BIN, profile.as_str()).map_err(CliError::from)?)
    };
    Ok(LoggedOut {
        session_removed: removed,
        revoked,
        browser_profile_removed: browser,
    })
}

// ----------------------------------------------------------------- reset

/// `auth reset`: every profile's sign-in and the vault's key, for a key
/// that is lost or damaged. Asks on a terminal and needs `--force`
/// otherwise (exit 6), decided before the vault is opened.
pub fn reset(force: bool, interactive: bool, env: &Env, json: bool, quiet: bool) -> Result<(), CliError> {
    pk_cli_core::confirm::require_confirmable(
        force,
        interactive,
        "remove every profile's Salve sign-in and the vault's key",
    )?;
    pk_cli_core::confirm::confirm(
        force,
        "Remove every profile's stored Salve sign-in and the vault's key? Each profile signs in again after",
    )?;
    let removed = (env.sessions)()?.clear()?;
    if json {
        output::json(&json!({ "schema": "auth-reset/v1", "sessions_removed": removed }));
    } else if !quiet {
        eprintln!("reset: {removed} stored sign-in(s) and the vault's key removed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sign_in_reads_two_lines_and_never_quotes_them() {
        let (u, p) = two_lines(&Secret::new(["someone@example.com", "hunter2", ""].join("\n"))).unwrap();
        assert_eq!((u.expose(), p.expose()), ("someone@example.com", "hunter2"));
        for bad in ["", "someone", "someone\n", "\nhunter2", "a\nb\nc"] {
            let e = two_lines(&Secret::new(bad)).unwrap_err();
            assert_eq!(e.exit_code(), 2, "{bad:?}");
            assert!(
                !e.message().contains("hunter2") && !e.message().contains("someone"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn an_op_item_names_its_two_fields() {
        let (u, p) = op_refs("op://Private/Some Login").unwrap();
        assert_eq!(u.as_str(), "op://Private/Some Login/username");
        assert_eq!(p.as_str(), "op://Private/Some Login/password");
        for bad in ["op://Private", "op://Private/Item/password", "Private/Item", "hunter2"] {
            assert!(!op_refs(bad).unwrap_err().message().contains(bad), "{bad}");
        }
    }

    #[test]
    fn the_key_needs_a_clinic() {
        let p = ProfileName::parse("adult1").unwrap();
        assert_eq!(LoginSettings::default().key(&p), None);
        let s = LoginSettings {
            clinic_id: Some("abc/123 x".into()),
            ..Default::default()
        };
        assert_eq!(s.key(&p).unwrap().to_string(), "adult1/abc_123_x/adult1");
    }

    #[test]
    fn the_page_tokens_are_read_by_the_web_clients_keys() {
        let e = storage_expression();
        assert!(e.contains(&format!("CognitoIdentityServiceProvider.{CLIENT_ID}.")));
        assert!(e.contains("LastAuthUser") && e.contains("refreshToken"));
    }
}
