//! Salve's records as FHIR R4 resources (records-stream/v1, method
//! `portal`).
//!
//! Salve is not a FHIR server, so every resource here is mapped, and says
//! so: `meta.source` is `salve:app` and `meta.tag` carries [`TAG_MAPPED`].
//! Ids are Salve's own ids with a prefix per kind (`doc-`, `file-`,
//! `form-`, `video-`, `msg-`, `cmsg-`, `att-`), so a resource keeps its id
//! across runs and the store's same-resource merge works.

use base64::Engine;
use serde_json::{json, Map, Value};

use crate::model::{AttachmentV3, DocumentItem, FileMeta, Form, MessageV0, MessageV3, VideoCall};

pub const TAG_SYSTEM: &str = "https://github.com/piekstra/salve-cli/fhir/tag";
pub const TAG_MAPPED: &str = "mapped-from-salve";
pub const META_SOURCE: &str = "salve:app";
const ACT_CODE_SYSTEM: &str = "http://terminology.hl7.org/CodeSystem/v3-ActCode";

/// What every mapped resource of one pull shares.
pub struct Ctx {
    /// Salve's portal address, the base of its local code systems.
    pub origin: String,
    /// `Patient/<id>`.
    pub patient: String,
    /// The clinic's name.
    pub clinic: String,
}

fn meta() -> Value {
    json!({
        "source": META_SOURCE,
        "tag": [{ "system": TAG_SYSTEM, "code": TAG_MAPPED, "display": "Mapped by salve from Salve's patient app" }],
    })
}

// ------------------------------------------------------------------ dates

/// A FHIR `dateTime` from a date text: ISO 8601, kept with its time when it
/// carries a zone and as the day when it does not; a number is read as
/// Unix milliseconds (or seconds). Years before 1902 are no date.
pub fn datetime(s: &str) -> Option<String> {
    let s = s.trim();
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        let n: u64 = s.parse().ok()?;
        let secs = if n > 100_000_000_000 { n / 1000 } else { n };
        let t = pk_cli_core::dates::fmt_rfc3339(secs as i64);
        return (t.as_str() >= "1902").then_some(t);
    }
    let day = s.get(..10)?;
    if !is_day(day) || day < "1902-01-01" {
        return None;
    }
    let Some(rest) = s.get(10..).filter(|r| !r.is_empty()) else {
        return Some(day.to_string());
    };
    let time = rest.strip_prefix('T').or_else(|| rest.strip_prefix(' '))?;
    let (clock, zone) = split_zone(time);
    let Some(zone) = zone else {
        return Some(day.to_string());
    };
    let (hms, frac) = match clock.split_once('.') {
        Some((h, f)) => (h, Some(f)),
        None => (clock, None),
    };
    let hms = match hms.len() {
        5 => format!("{hms}:00"),
        8 => hms.to_string(),
        _ => return Some(day.to_string()),
    };
    let ok = hms.bytes().enumerate().all(|(i, b)| {
        if i == 2 || i == 5 {
            b == b':'
        } else {
            b.is_ascii_digit()
        }
    });
    if !ok || &hms[..2] > "23" || &hms[3..5] > "59" || &hms[6..8] > "60" {
        return Some(day.to_string());
    }
    let frac = frac
        .filter(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
        .map(|f| format!(".{}", &f[..f.len().min(9)]))
        .unwrap_or_default();
    Some(format!("{day}T{hms}{frac}{zone}"))
}

/// A FHIR `instant`: a [`datetime`] with its time and zone, else none.
pub fn instant(s: &str) -> Option<String> {
    datetime(s).filter(|d| d.len() > 10)
}

/// The day (`YYYY-MM-DD`) a date text names.
pub fn day(s: &str) -> Option<String> {
    datetime(s).map(|d| d[..10].to_string())
}

fn is_day(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
        && ("01"..="12").contains(&&s[5..7])
        && ("01"..="31").contains(&&s[8..10])
}

/// A clock time and its zone (`Z`, `+hh:mm`, `-hh:mm`, `+hhmm`), the zone
/// normalized to `+hh:mm`.
fn split_zone(time: &str) -> (&str, Option<String>) {
    if let Some(clock) = time.strip_suffix('Z') {
        return (clock, Some("Z".into()));
    }
    let Some(pos) = time.rfind(['+', '-']) else {
        return (time, None);
    };
    let (clock, zone) = time.split_at(pos);
    let digits: String = zone[1..].chars().filter(|c| *c != ':').collect();
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) || &digits[..2] > "14" {
        return (time, None);
    }
    (clock, Some(format!("{}{}:{}", &zone[..1], &digits[..2], &digits[2..])))
}

// --------------------------------------------------------------- resources

fn set(map: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(v) = value {
        map.insert(key.to_string(), v);
    }
}

fn text_of(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The patient: Salve's id, the name and the birth date the sign-in read.
pub fn patient(
    ctx: &Ctx,
    id: &str,
    full: Option<&str>,
    first: Option<&str>,
    last: Option<&str>,
    birth: Option<&str>,
) -> Value {
    let mut p = Map::new();
    p.insert("resourceType".into(), json!("Patient"));
    p.insert("id".into(), json!(id));
    p.insert("meta".into(), meta());
    p.insert(
        "identifier".into(),
        json!([{ "system": format!("{}/patient-id", ctx.origin), "value": id }]),
    );
    let mut name = Map::new();
    let full = full.map(str::to_string).or_else(|| match (first, last) {
        (Some(f), Some(l)) => Some(format!("{f} {l}")),
        _ => None,
    });
    set(&mut name, "text", full.map(|s| json!(s)));
    set(&mut name, "family", last.map(|s| json!(s)));
    set(&mut name, "given", first.map(|s| json!([s])));
    if !name.is_empty() {
        p.insert("name".into(), json!([Value::Object(name)]));
    }
    set(&mut p, "birthDate", birth.and_then(day).map(|d| json!(d)));
    Value::Object(p)
}

/// A file's content type: what Salve says it is, else by its name, else by
/// its first bytes.
pub fn content_type(filetype: Option<&str>, name: Option<&str>, bytes: Option<&[u8]>) -> String {
    if let Some(t) = filetype
        .map(str::trim)
        .filter(|t| t.contains('/') && !t.contains(char::is_whitespace))
    {
        return t.to_ascii_lowercase();
    }
    let ext = filetype
        .map(|t| t.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|t| !t.is_empty() && t.len() <= 5)
        .or_else(|| {
            name.and_then(|n| n.rsplit_once('.'))
                .map(|(_, e)| e.to_ascii_lowercase())
        })
        .unwrap_or_default();
    let by_ext = match ext.as_str() {
        "pdf" => Some("application/pdf"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "tif" | "tiff" => Some("image/tiff"),
        "heic" => Some("image/heic"),
        "txt" => Some("text/plain"),
        "doc" => Some("application/msword"),
        "docx" => Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        _ => None,
    };
    if let Some(t) = by_ext {
        return t.into();
    }
    match bytes.and_then(pk_cli_documents::sniff) {
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("tiff") => "image/tiff",
        _ => "application/octet-stream",
    }
    .into()
}

/// A document the clinic sent (`doc-`) or a file on the record (`file-`),
/// as a DocumentReference naming its Binary when it was fetched.
pub fn document(ctx: &Ctx, prefix: &str, kind: &str, d: &DocumentItem, binary: Option<&str>) -> Option<Value> {
    let id = text_of(&d.id)?;
    let rid = format!("{prefix}-{id}");
    let name = text_of(&d.name);
    let mut r = Map::new();
    r.insert("resourceType".into(), json!("DocumentReference"));
    r.insert("id".into(), json!(rid));
    r.insert("meta".into(), meta());
    r.insert("status".into(), json!("current"));
    r.insert("type".into(), json!({ "text": kind }));
    r.insert("subject".into(), json!({ "reference": ctx.patient }));
    set(
        &mut r,
        "date",
        d.sentdate.as_deref().and_then(instant).map(|s| json!(s)),
    );
    r.insert("custodian".into(), json!({ "display": ctx.clinic }));
    set(&mut r, "description", name.clone().map(|n| json!(n)));
    let mut a = Map::new();
    if let Some(ctype) = binary {
        a.insert("contentType".into(), json!(ctype));
        a.insert("url".into(), json!(format!("Binary/{rid}")));
    }
    set(&mut a, "title", name.map(|n| json!(n)));
    set(
        &mut a,
        "creation",
        d.sentdate.as_deref().and_then(datetime).map(|s| json!(s)),
    );
    r.insert("content".into(), json!([{ "attachment": Value::Object(a) }]));
    Some(Value::Object(r))
}

/// A form the patient filled in, as a DocumentReference of Salve's own JSON:
/// the form's definition and the patient's latest answers, as Salve keeps
/// them.
pub fn form_document(ctx: &Ctx, id: &str, f: &Form, status: Option<&str>) -> Value {
    let title = text_of(&f.name).unwrap_or_else(|| "Form".into());
    let mut r = Map::new();
    r.insert("resourceType".into(), json!("DocumentReference"));
    r.insert("id".into(), json!(id));
    r.insert("meta".into(), meta());
    r.insert("status".into(), json!("current"));
    let complete = status.is_some_and(|s| s.eq_ignore_ascii_case("complete"))
        || f.latestsubmission.as_ref().and_then(|s| s.issubmitted) == Some(true);
    r.insert(
        "docStatus".into(),
        json!(if complete { "final" } else { "preliminary" }),
    );
    r.insert("type".into(), json!({ "text": "Form" }));
    r.insert(
        "category".into(),
        json!([{ "text": text_of(&f.kind).unwrap_or_else(|| "form".into()) }]),
    );
    r.insert("subject".into(), json!({ "reference": ctx.patient }));
    r.insert("custodian".into(), json!({ "display": ctx.clinic }));
    r.insert("description".into(), json!(title));
    r.insert(
        "content".into(),
        json!([{ "attachment": { "contentType": "application/json", "url": format!("Binary/{id}"), "title": title } }]),
    );
    Value::Object(r)
}

/// A video visit as an Encounter of class `VR` (virtual): planned before
/// its start, finished after its end.
pub fn video_encounter(ctx: &Ctx, v: &VideoCall, now: &str) -> Option<Value> {
    let id = text_of(&v.id)?;
    let start = v.startdate.as_deref().and_then(datetime);
    let end = v.enddate.as_deref().and_then(datetime);
    let status = match (&start, &end) {
        (Some(s), _) if s.as_str() > now => "planned",
        (_, Some(e)) if e.as_str() <= now => "finished",
        (Some(_), None) => "finished",
        _ => "unknown",
    };
    let mut e = Map::new();
    e.insert("resourceType".into(), json!("Encounter"));
    e.insert("id".into(), json!(format!("video-{id}")));
    e.insert("meta".into(), meta());
    e.insert("status".into(), json!(status));
    e.insert(
        "class".into(),
        json!({ "system": ACT_CODE_SYSTEM, "code": "VR", "display": "virtual" }),
    );
    let kind = text_of(&v.title)
        .or_else(|| text_of(&v.name))
        .unwrap_or_else(|| "Video visit".into());
    e.insert("type".into(), json!([{ "text": kind }]));
    e.insert("subject".into(), json!({ "reference": ctx.patient }));
    let mut period = Map::new();
    set(&mut period, "start", start.map(|s| json!(s)));
    set(&mut period, "end", end.map(|s| json!(s)));
    if !period.is_empty() {
        e.insert("period".into(), Value::Object(period));
    }
    set(
        &mut e,
        "length",
        v.duration
            .filter(|d| *d > 0)
            .map(|d| json!({ "value": d, "unit": "minutes", "system": "http://unitsofmeasure.org", "code": "min" })),
    );
    set(
        &mut e,
        "participant",
        text_of(&v.host).map(|h| json!([{ "individual": { "display": h } }])),
    );
    set(
        &mut e,
        "reasonCode",
        text_of(&v.description).map(|d| json!([{ "text": d }])),
    );
    e.insert("serviceProvider".into(), json!({ "display": ctx.clinic }));
    Some(Value::Object(e))
}

/// A message's attachment, as a DocumentReference naming its Binary.
pub fn attachment_document(
    ctx: &Ctx,
    id: &str,
    name: Option<&str>,
    msg: &str,
    sent: Option<&str>,
    ctype: &str,
) -> Value {
    let mut d = Map::new();
    d.insert("resourceType".into(), json!("DocumentReference"));
    d.insert("id".into(), json!(id));
    d.insert("meta".into(), meta());
    d.insert("status".into(), json!("current"));
    d.insert("type".into(), json!({ "text": "Message attachment" }));
    d.insert("subject".into(), json!({ "reference": ctx.patient }));
    set(&mut d, "date", sent.and_then(instant).map(|s| json!(s)));
    d.insert("custodian".into(), json!({ "display": ctx.clinic }));
    let name = name.map(str::trim).filter(|n| !n.is_empty());
    set(&mut d, "description", name.map(|n| json!(n)));
    let mut att = Map::new();
    att.insert("contentType".into(), json!(ctype));
    att.insert("url".into(), json!(format!("Binary/{id}")));
    set(&mut att, "title", name.map(|n| json!(n)));
    d.insert("content".into(), json!([{ "attachment": Value::Object(att) }]));
    d.insert(
        "context".into(),
        json!({ "related": [{ "reference": format!("Communication/{msg}") }] }),
    );
    Value::Object(d)
}

/// The conversation a message belongs to, as Communication.topic.
fn topic(ctx: &Ctx, conversation: i64, subject: Option<&str>) -> Value {
    let mut t =
        json!({ "coding": [{ "system": format!("{}/conversation", ctx.origin), "code": conversation.to_string() }] });
    if let Some(s) = subject.map(str::trim).filter(|s| !s.is_empty()) {
        t["text"] = json!(s);
        t["coding"][0]["display"] = json!(s);
    }
    t
}

fn payload(text: Option<String>, attachments: &[String]) -> Option<Value> {
    let mut p = Vec::new();
    if let Some(t) = text {
        p.push(json!({ "contentString": t }));
    }
    for a in attachments {
        p.push(json!({ "contentReference": { "reference": format!("DocumentReference/{a}") } }));
    }
    (!p.is_empty()).then_some(Value::Array(p))
}

/// A message of the first messaging as a Communication.
pub fn communication_v0(
    ctx: &Ctx,
    conversation: i64,
    subject: Option<&str>,
    m: &MessageV0,
    attachments: &[String],
) -> Option<Value> {
    let id = text_of(&m.id)?;
    let mut c = Map::new();
    c.insert("resourceType".into(), json!("Communication"));
    c.insert("id".into(), json!(format!("msg-{id}")));
    c.insert("meta".into(), meta());
    c.insert("status".into(), json!("completed"));
    c.insert("subject".into(), json!({ "reference": ctx.patient }));
    c.insert("topic".into(), topic(ctx, conversation, subject));
    set(&mut c, "sent", m.sent.as_deref().and_then(datetime).map(|s| json!(s)));
    let sender = text_of(&m.sender);
    if m.frompatient == Some(true) {
        let mut s = json!({ "reference": ctx.patient });
        if let Some(n) = &sender {
            s["display"] = json!(n);
        }
        c.insert("sender".into(), s);
        c.insert("recipient".into(), json!([{ "display": ctx.clinic }]));
    } else {
        c.insert(
            "sender".into(),
            json!({ "display": sender.clone().unwrap_or_else(|| ctx.clinic.clone()) }),
        );
        c.insert("recipient".into(), json!([{ "reference": ctx.patient }]));
    }
    set(&mut c, "payload", payload(text_of(&m.content), attachments));
    Some(Value::Object(c))
}

/// A message of the newer messaging as a Communication.
pub fn communication_v3(
    ctx: &Ctx,
    conversation: i64,
    subject: Option<&str>,
    m: &MessageV3,
    from_patient: bool,
    attachments: &[String],
) -> Option<Value> {
    let id = text_of(&m.id)?;
    let mut c = Map::new();
    c.insert("resourceType".into(), json!("Communication"));
    c.insert("id".into(), json!(format!("cmsg-{id}")));
    c.insert("meta".into(), meta());
    c.insert("status".into(), json!("completed"));
    c.insert("subject".into(), json!({ "reference": ctx.patient }));
    c.insert("topic".into(), topic(ctx, conversation, subject));
    set(
        &mut c,
        "sent",
        m.sent_date.as_deref().and_then(datetime).map(|s| json!(s)),
    );
    if from_patient {
        let mut s = json!({ "reference": ctx.patient });
        if let Some(n) = m.patient.as_ref().and_then(|p| p.display()) {
            s["display"] = json!(n);
        }
        c.insert("sender".into(), s);
        c.insert("recipient".into(), json!([{ "display": ctx.clinic }]));
    } else {
        let who = m
            .clinic_user
            .as_ref()
            .and_then(|u| u.display())
            .unwrap_or_else(|| ctx.clinic.clone());
        c.insert("sender".into(), json!({ "display": who }));
        c.insert("recipient".into(), json!([{ "reference": ctx.patient }]));
    }
    set(&mut c, "payload", payload(text_of(&m.content), attachments));
    Some(Value::Object(c))
}

/// An attachment's id: `att-` and Salve's uuid for it, else its id.
pub fn meta_id(f: &FileMeta) -> Option<String> {
    text_of(&f.uuid).or_else(|| text_of(&f.id)).map(|i| format!("att-{i}"))
}

pub fn attachment_v3_id(a: &AttachmentV3) -> Option<String> {
    text_of(&a.uuid).map(|i| format!("att-{i}"))
}

/// A Binary: the file's bytes, base64.
pub fn binary(id: &str, content_type: &str, bytes: &[u8]) -> Value {
    json!({
        "resourceType": "Binary",
        "id": id,
        "meta": meta(),
        "contentType": content_type,
        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Ctx {
        Ctx {
            origin: "https://patientwebportal.salvehealth.com".into(),
            patient: "Patient/1001".into(),
            clinic: "Example Fertility".into(),
        }
    }

    #[test]
    fn dates_keep_their_zone_or_become_a_day() {
        assert_eq!(
            datetime("2025-03-04T10:20:30.123Z").as_deref(),
            Some("2025-03-04T10:20:30.123Z")
        );
        assert_eq!(
            datetime("2025-03-04T10:20:30+0100").as_deref(),
            Some("2025-03-04T10:20:30+01:00")
        );
        assert_eq!(datetime("2025-03-04T10:20:30").as_deref(), Some("2025-03-04"));
        assert_eq!(datetime("2025-03-04").as_deref(), Some("2025-03-04"));
        // Unix seconds, and milliseconds.
        assert_eq!(datetime("1111111111").as_deref(), Some("2005-03-18T01:58:31Z"));
        assert_eq!(
            datetime(&format!("{}000", "1111111111")).as_deref(),
            Some("2005-03-18T01:58:31Z")
        );
        assert_eq!(datetime("0001-01-01T00:00:00Z"), None);
        assert_eq!(datetime("not a date"), None);
        assert_eq!(day("2025-03-04T23:20:30-05:00").as_deref(), Some("2025-03-04"));
    }

    #[test]
    fn content_types_come_from_salve_then_the_name_then_the_bytes() {
        assert_eq!(content_type(Some("application/pdf"), None, None), "application/pdf");
        assert_eq!(content_type(Some("PDF"), None, None), "application/pdf");
        assert_eq!(content_type(None, Some("scan.JPG"), None), "image/jpeg");
        assert_eq!(content_type(None, Some("x"), Some(b"%PDF-1.4")), "application/pdf");
        assert_eq!(content_type(None, None, Some(b"plain")), "application/octet-stream");
    }

    #[test]
    fn a_video_visit_is_planned_or_finished_by_its_dates() {
        let v = VideoCall {
            id: Some("7".into()),
            title: Some("Follow-up".into()),
            startdate: Some("2030-01-01T09:00:00Z".into()),
            enddate: Some("2030-01-01T09:30:00Z".into()),
            duration: Some(30),
            ..Default::default()
        };
        let e = video_encounter(&ctx(), &v, "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(e["status"], "planned");
        assert_eq!(e["class"]["code"], "VR");
        assert_eq!(e["length"]["value"], 30);
        let e = video_encounter(&ctx(), &v, "2031-01-01T00:00:00Z").unwrap();
        assert_eq!(e["status"], "finished");
    }

    #[test]
    fn a_message_names_who_sent_it() {
        let from_clinic = MessageV0 {
            id: Some("5".into()),
            content: Some("Hello".into()),
            sender: Some("Nurse Example".into()),
            frompatient: Some(false),
            sent: Some("2025-01-02T03:04:05Z".into()),
            ..Default::default()
        };
        let c = communication_v0(&ctx(), 9, Some("Nursing"), &from_clinic, &["att-1".into()]).unwrap();
        assert_eq!(c["sender"]["display"], "Nurse Example");
        assert_eq!(c["recipient"][0]["reference"], "Patient/1001");
        assert_eq!(c["topic"]["coding"][0]["code"], "9");
        assert_eq!(
            c["payload"][1]["contentReference"]["reference"],
            "DocumentReference/att-1"
        );
        let from_patient = MessageV0 {
            frompatient: Some(true),
            ..from_clinic
        };
        let c = communication_v0(&ctx(), 9, None, &from_patient, &[]).unwrap();
        assert_eq!(c["sender"]["reference"], "Patient/1001");
    }
}
