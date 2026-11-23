//! Current platform protocol. The desktop host and socket acceptance use this
//! path; legacy DTO/codec/simulation modules remain reference-only.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::device_code::compact_device_code;
use std::{collections::HashSet, fmt, fs, io::{Read,Write}, path::Path, time::{Duration, Instant}};

type Result<T> = std::result::Result<T, String>;
pub const AUTH_SCHEMA: &str = include_str!("current_contracts/authorization.v1.schema.json");
pub const LOCAL_SCHEMA: &str = include_str!("current_contracts/authorization-a-core.v1.schema.json");
pub const PROOF_CONTRACT: &str = include_str!("current_contracts/device-proof.v1.json");
const MAX_JSON: usize = 2_000_000;
const IDENTITY: [&str; 6] = ["software_id", "profile_id", "client_id", "target", "arch", "channel"];
const TIMES: [&str; 6] = ["issued_at", "expires_at", "server_time", "cache_until", "next_verify_at", "grace_until"];

// serde_json handles UTF-8, escapes, surrogate pairs and numeric syntax. This
// visitor adds duplicate-key rejection BEFORE serde's Value could discard one.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("JSON without duplicate keys") }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique,E> { Ok(Unique(v.into())) }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique,E> { Ok(Unique(v.into())) }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique,E> { Ok(Unique(v.into())) }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique,E> {
                serde_json::Number::from_f64(v).map(|n| Unique(Value::Number(n))).ok_or_else(|| E::custom("nonfinite"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique,E> { Ok(Unique(v.into())) }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique,E> { Ok(Unique(v.into())) }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique,E> { Ok(Unique(Value::Null)) }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique,E> { Ok(Unique(Value::Null)) }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Unique,A::Error> {
                let mut out = Vec::new();
                while let Some(Unique(v)) = a.next_element()? { out.push(v); }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Unique,A::Error> {
                let mut out = Map::new();
                while let Some((k, Unique(v))) = a.next_entry::<String, Unique>()? {
                    if out.insert(k, v).is_some() { return Err(de::Error::custom("duplicate key")); }
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_JSON { return Err("JSON size limit".into()); }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let Unique(v) = Unique::deserialize(&mut d).map_err(|_| "Invalid or duplicate JSON")?;
    d.end().map_err(|_| "Trailing JSON")?;
    fn bounded(v: &Value, depth: usize) -> bool {
        depth <= 32 && match v {
            Value::Array(a) => a.iter().all(|v| bounded(v,depth+1)),
            Value::Object(a) => a.values().all(|v| bounded(v,depth+1)), _ => true
        }
    }
    if !bounded(&v, 0) { return Err("JSON depth limit".into()); }
    Ok(v)
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v[field].as_str().filter(|s| !s.trim().is_empty() && !s.chars().any(char::is_control)).ok_or_else(|| format!("Invalid {field}"))
}
fn epoch(v: &Value, field: &str) -> Result<i64> { v[field].as_i64().ok_or_else(|| format!("Invalid int64 {field}")) }
fn equal(a: &Value, b: &Value, fields: &[&str]) -> Result<()> {
    if fields.iter().any(|k| a[*k] != b[*k]) { return Err("Response scope mismatch".into()); } Ok(())
}
fn random_id() -> String {
    let mut b = [0u8; 24]; OsRng.fill_bytes(&mut b); URL_SAFE_NO_PAD.encode(b)
}

/// Only signature verification can construct this. No DTO projection loses
/// extensions, floats, Unicode keys or integrity metadata before verification.
#[derive(Clone)]
pub struct VerifiedDocument(Value);
pub fn verify_signed(v: &Value, key_id: &str, key: &VerifyingKey) -> Result<VerifiedDocument> {
    let i = &v["integrity"];
    if i["algorithm"] != "ed25519" || i["canonicalization"] != "JCS-RFC8785" || i["key_id"] != key_id {
        return Err("Unknown signature identity".into());
    }
    let raw = URL_SAFE_NO_PAD.decode(text(i,"signature")?).map_err(|_| "Invalid signature encoding")?;
    let signature = Signature::from_slice(&raw).map_err(|_| "Invalid signature size")?;
    let mut signable = v.clone(); signable["integrity"].as_object_mut().ok_or("Invalid integrity")?.remove("signature");
    let bytes = serde_jcs::to_vec(&signable).map_err(|_| "JCS failed")?;
    key.verify_strict(&bytes, &signature).map_err(|_| "Invalid Ed25519 signature")?;
    Ok(VerifiedDocument(v.clone()))
}
fn sign(mut v: Value, key: &SigningKey) -> Result<Value> {
    v["integrity"].as_object_mut().ok_or("Missing integrity")?.remove("signature");
    v["integrity"]["signature"] = URL_SAFE_NO_PAD.encode(key.sign(&serde_jcs::to_vec(&v).map_err(|_| "JCS failed")?).to_bytes()).into();
    Ok(v)
}

#[derive(Clone)]
pub struct Binding { value: Value, auth_validator:std::sync::Arc<jsonschema::Validator>, local_validator:std::sync::Arc<jsonschema::Validator>, key: VerifyingKey, version: String }
impl Binding {
    pub fn load(folder: &Path, current_version: &str) -> Result<Self> {
        if current_version.split('.').count() != 3 || !current_version.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
            return Err("Supply the real three-component build version".into());
        }
        let value = parse_json(&fs::read(folder.join("platform-binding.json")).map_err(|_| "Missing prepared binding")?)?;
        if value["schema"] != "authorization-a-platform-binding.v1" { return Err("Unsupported prepared binding".into()); }
        let raw = fs::read(folder.join("source-integration.json")).map_err(|_| "Missing original v2 export")?;
        if value["source_sha256"] != format!("{:x}", Sha256::digest(&raw)) { return Err("Source digest mismatch".into()); }
        let source = parse_json(&raw)?;
        if source["schema"] != "software-bind.v2" { return Err("Unsupported software export".into()); }
        equal(&source,&value,&["platform","software","api","authorization_a","core","response_contracts"])?;
        let auth_schema = parse_json(AUTH_SCHEMA.as_bytes())?;
        let local_schema = parse_json(LOCAL_SCHEMA.as_bytes())?;
        for (name, expected) in [("authorization.v1.schema.json", &auth_schema), ("authorization-a-core.v1.schema.json", &local_schema), ("device-proof.v1.json", &parse_json(PROOF_CONTRACT.as_bytes())?)] {
            if &source["contracts"][name] != expected || parse_json(&fs::read(folder.join(name)).map_err(|_| "Missing prepared contract")?)? != *expected {
                return Err("Unsupported or damaged embedded contract".into());
            }
        }
        let p = &value["platform"];
        if p["contract_version"] != "authorization.v1" || p["algorithm"] != "ed25519" || p["canonicalization"] != "JCS-RFC8785" || p["encoding"] != "base64url-no-padding" {
            return Err("Unsupported platform signature contract".into());
        }
        let url = url::Url::parse(text(p,"base_url")?).map_err(|_| "Invalid platform origin")?;
        let local = value["environment"] == "local" && url.scheme() == "http" && matches!(url.host_str(),Some("127.0.0.1"|"localhost"|"::1"|"[::1]"));
        if !(url.scheme()=="https" || local) || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || url.path()!="/" {
            return Err("Expected HTTPS origin; loopback HTTP needs explicit local preparation".into());
        }
        for k in IDENTITY { let s=text(&value["software"],k)?; if s.chars().count()>128 || s.trim()!=s { return Err("Invalid software identity".into()); } }
        for (name, suffix) in [("activate","activate"),("verify","verify"),("deactivate","deactivate"),("launch_ticket","launch-ticket"),("consume_launch_ticket","launch-ticket/consume")] {
            if value["api"][name] != format!("/api/v1/public/licenses/{suffix}") { return Err("Unsupported API route".into()); }
        }
        if value["core"] != json!({"talks_to_platform":false,"talks_to_local_a_only":true}) || value["authorization_a"] != json!({"copy_from_master":true,"local_contract_version":"authorization-a-core.v1","local_bind_policy":"127.0.0.1-only"}) {
            return Err("Unsupported core boundary".into());
        }
        let bytes=URL_SAFE_NO_PAD.decode(text(p,"authorization_public_key")?).map_err(|_| "Bad public key")?;
        let key = VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| "Bad public key size")?).map_err(|_| "Bad public key")?;
        let auth_validator=std::sync::Arc::new(jsonschema::validator_for(&auth_schema).map_err(|_|"Invalid authorization schema")?);
        let local_validator=std::sync::Arc::new(jsonschema::validator_for(&local_schema).map_err(|_|"Invalid local schema")?);
        Ok(Self{value,auth_validator,local_validator,key,version:current_version.into()})
    }
}

/// Successful response clock, exclusive card expiry, and retry clock are
/// independent. Only ordinary authorization success replaces the online
/// window; accepted ticket time can only advance the trusted clock.
#[derive(Default)]
pub struct LiveSession {
    response: Option<Value>, clock: Option<(i64,Instant)>, highwater: Option<i64>,
    online_deadline: Option<Instant>, refresh_at: Option<Instant>,
    decision: Option<String>, retry_at: Option<Instant>, terminal: bool,
    request_ids: HashSet<String>,
}
impl LiveSession {
    pub fn response(&self) -> Option<&Value> { self.response.as_ref() }
    pub fn accept(&mut self, document: VerifiedDocument, now: Instant) -> Result<()> {
        let v = document.0;
        let id=text(&v,"request_id")?.to_string();
        if self.terminal || self.request_ids.contains(&id) { return Err("Terminal or replayed session response".into()); }
        let server = epoch(&v,"server_time")?;
        for field in TIMES { epoch(&v,field)?; }
        let mut decision=text(&v,"decision")?.to_string();
        let revision=v["authorization_revision"].as_u64().filter(|r| *r>0).ok_or("Bad revision")?;
        if let Some(old)=&self.response {
            equal(old,&v,&["authorization_id","issued_at"])?;
            if matches!(v["decision"].as_str(),Some("active"|"grace"|"not_modified")) {equal(old,&v,&["device_scope"])?;}
            if server<self.highwater.unwrap_or(epoch(old,"server_time")?) || revision<old["authorization_revision"].as_u64().ok_or("Bad revision")? { return Err("Stale signed response".into()); }
            if revision==old["authorization_revision"].as_u64().unwrap() {
                // request/time/signature change on ordinary same-revision verify.
                equal(old,&v,&["expires_at"])?;
            }
            if decision=="not_modified" {
                equal(old,&v,&["authorization_revision","config_version","expires_at"])?;
                decision=self.decision.clone().ok_or("Missing effective decision")?;
            }
        } else if decision=="not_modified" { return Err("not_modified without session".into()); }
        let active=matches!(decision.as_str(),"active"|"grace");
        if active && epoch(&v,"next_verify_at")?<=server {return Err("Empty online success window".into());}
        if active && (epoch(&v,"issued_at")?>server || server>=epoch(&v,"expires_at")? || epoch(&v,"cache_until")?!=epoch(&v,"next_verify_at")? || epoch(&v,"next_verify_at")?<server || epoch(&v,"next_verify_at")?>epoch(&v,"expires_at")?) {
            return Err("Invalid authorization times".into());
        }
        let expiry=epoch(&v,"expires_at")?;
        let interval=Duration::from_secs(epoch(&v,"next_verify_at")?.saturating_sub(server).max(0) as u64);
        let grace=Duration::from_secs(epoch(&v,"grace_until")?.saturating_sub(expiry).max(0) as u64);
        let lead=(interval/2).min(Duration::from_secs(3));
        // `now` is the FIRST attempt of this correlated ordinary request,
        // never its receive/retry time. A fresh same-second success replaces
        // this budget without rewinding the independent trusted card clock.
        let online_deadline=now.checked_add(interval).and_then(|end|end.checked_add(grace)).ok_or("Online deadline overflow")?;
        let refresh_at=now.checked_add(interval-lead).ok_or("Refresh deadline overflow")?;
        self.terminal=!active;
        // Correlation is also enforced by the host. A bounded recent replay set
        // is sufficient; there is no lifetime request budget or 1024 lockout.
        if self.request_ids.len()>=2048 { self.request_ids.clear(); }
        self.request_ids.insert(id);
        self.advance_time(server,now);
        self.online_deadline=Some(online_deadline);self.refresh_at=Some(refresh_at);
        self.decision=Some(decision);self.response=Some(v);self.retry_at=None;Ok(())
    }
    pub fn trusted_time(&self, now: Instant) -> Option<i64> {
        let (server,anchor)=self.clock?;
        let delta=now.checked_duration_since(anchor).unwrap_or_default().as_secs();
        server.checked_add(i64::try_from(delta).ok()?)
    }
    // Private: callers must first validate the complete endpoint response,
    // scope, correlation, signature (issued), and ticket time constraints.
    fn advance_time(&mut self, server:i64, observed:Instant) {
        self.highwater=Some(self.highwater.map_or(server,|old|old.max(server)));
        // Keeping the existing mapping on equal/older time also keeps its
        // fractional second. Reanchoring it would silently buy extra time.
        if self.trusted_time(observed).map_or(true,|old|server>old) {self.clock=Some((server,observed));}
    }
    fn mapped_deadline(&self, epoch:i64) -> Option<Instant> {
        let (server,anchor)=self.clock?;
        anchor.checked_add(Duration::from_secs(epoch.saturating_sub(server).max(0) as u64))
    }
    fn accept_ticket_time(&mut self, server:i64, observed:Instant) {
        let advance=self.mapped_deadline(server).and_then(|target|target.checked_duration_since(observed));
        self.advance_time(server,observed);
        // Tickets cannot replace ordinary success. Advancing trusted time can
        // only subtract the clock jump from its remaining budget. Equal time
        // leaves it intact; deriving it again from the signed integer `next`
        // would discard a fresh same-second success. Keep subsecond progress.
        if let Some(advance)=advance {
            self.online_deadline=self.online_deadline.and_then(|end|end.checked_sub(advance));
            self.refresh_at=self.refresh_at.and_then(|end|end.checked_sub(advance));
        }
    }
    pub fn usable(&self, now: Instant) -> bool {
        self.deadline().map_or(false,|end|now<end)
    }
    pub fn deadline(&self) -> Option<Instant> {
        if self.terminal {return None;}
        let v=self.response.as_ref()?;let expiry=epoch(v,"expires_at").ok()?;
        Some(self.online_deadline?.min(self.mapped_deadline(expiry)?))
    }
    pub fn due(&self, now: Instant) -> bool {
        if self.terminal || self.response.is_none() {return false;}
        if let Some(retry)=self.retry_at {return now>=retry;}
        // Leave room for network I/O and the 250ms worker/watch cadence.
        // This schedules a request; it never moves the success deadline.
        self.refresh_at.map_or(true,|refresh|now>=refresh)
    }
    pub fn retry_after(&mut self, now: Instant, delay: Duration) { self.retry_at=Some(now+delay.min(Duration::from_secs(300))); }
    pub fn invalidate(&mut self) { self.terminal=true; }
}

struct Pending { action: String, path: String, body: Value, issued: Option<Value>, started:Instant }
#[derive(Clone,Default)]
pub struct DeadlineMonitor(std::sync::Arc<std::sync::Mutex<Option<Instant>>>);
impl DeadlineMonitor {
    pub fn deadline(&self)->Option<Instant> {self.0.lock().ok().and_then(|value|*value)}
}
pub struct DesktopHost {
    binding: Binding, device: SigningKey, local: SigningKey, installation: String,
    agent: ureq::Agent, session: LiveSession, pending: Option<Pending>, launch: Option<LaunchPermit>,
    error: Option<String>, launched: bool, watched_deadline:DeadlineMonitor,
}
/// A one-use result, never an issued-only or locally fabricated ticket.
pub struct LaunchPermit { pub ticket_id: String, pub authorization_id: String, deadline:Instant }
impl DesktopHost {
    pub fn new(binding: Binding, installation: String, device: SigningKey) -> Result<Self> {
        if installation.trim()!=installation || installation.is_empty() || installation.chars().count()>128 || installation.chars().any(char::is_control) {return Err("Invalid stable installation identity".into());}
        Ok(Self{binding,device,local:SigningKey::generate(&mut OsRng),installation,
            agent:ureq::AgentBuilder::new().timeout(Duration::from_secs(3)).redirects(0).build(),
            session:LiveSession::default(), pending:None,launch:None,error:None,launched:false,
            watched_deadline:DeadlineMonitor::default()})
    }
    /// Readable by the core watch without waiting on a network-held host lock.
    pub fn deadline_monitor(&self)->DeadlineMonitor {self.watched_deadline.clone()}
    fn publish_deadline(&self) {if let Ok(mut watched)=self.watched_deadline.0.lock(){*watched=self.session.deadline();}}
    fn request(&self, action: &str, credential: Option<&str>, ticket: Option<&str>) -> Result<Pending> {
        let mut body=Map::new();
        for k in IDENTITY {body.insert(k.into(), self.binding.value["software"][k].clone());}
        let id=random_id();
        body.extend(json!({"contract_version":"authorization.v1","request_id":id,"idempotency_key":id,
            "installation_id":self.installation,"device_public_key":URL_SAFE_NO_PAD.encode(self.device.verifying_key().to_bytes()),
            "client_version":self.binding.version,"nonce":random_id()}).as_object().unwrap().clone());
        if action=="activate" {body.insert("license_key".into(),credential.ok_or("Missing credential")?.trim().into());}
        else {body.insert("authorization_id".into(),self.session.response().ok_or("No authorization")?["authorization_id"].clone());}
        if action=="verify" {
            let previous=self.session.response().ok_or("No session")?;
            body.insert("known_authorization_revision".into(),previous["authorization_revision"].clone());
            body.insert("known_config_version".into(),previous["config_version"].clone());
        }
        if let Some(ticket)=ticket {body.insert("ticket_id".into(),ticket.into());}
        let mut proof=json!({"domain":"authorization-platform.device-proof.v1","action":action,"authorization_id":""});
        for k in ["request_id","authorization_id","software_id","profile_id","client_id","contract_version","target","arch","channel","installation_id","device_public_key","nonce"] {
            if let Some(v)=body.get(k) {proof[k]=v.clone();}
        }
        body.insert("device_proof".into(),URL_SAFE_NO_PAD.encode(self.device.sign(&serde_jcs::to_vec(&proof).map_err(|_| "JCS proof")?).to_bytes()).into());
        let name=match action {"launch-ticket"=>"launch_ticket","ticket-consume"=>"consume_launch_ticket",x=>x};
        Ok(Pending{action:action.into(),path:text(&self.binding.value["api"],name)?.into(),body:Value::Object(body),issued:None,started:Instant::now()})
    }
    fn exchange(&mut self, pending: &Pending) -> Result<(Value, Instant)> {
        let id=text(&pending.body,"request_id")?;
        let url=format!("{}{}",text(&self.binding.value["platform"],"base_url")?.trim_end_matches('/'),pending.path);
        let response=self.agent.post(&url).set("Content-Type","application/json").set("X-Request-Id",id).set("Idempotency-Key",text(&pending.body,"idempotency_key")?).send_string(&serde_json::to_string(&pending.body).map_err(|_| "Request encoding")?);
        let response=match response {
            Ok(r)=>r,Err(ureq::Error::Status(_,r))=>r,
            Err(_)=>{self.session.retry_after(Instant::now(),Duration::from_secs(5)); return Err("NETWORK_RETRY".into());}
        };
        // Anchor at the start of the response; slow reading cannot add time.
        let received=Instant::now();
        let status=response.status();
        if status==429 || status>=500 {
            let delay=response.header("Retry-After").and_then(|s| s.parse::<u64>().ok()).unwrap_or(5).clamp(1,300);
            self.session.retry_after(received,Duration::from_secs(delay));
            return Err(if status==429 {"RATE_LIMITED_RETRY"} else {"SERVER_RETRY"}.into());
        }
        let mut bytes=Vec::new();response.into_reader().take((MAX_JSON+1) as u64).read_to_end(&mut bytes).map_err(|_| "Response read failed")?;
        let v=parse_json(&bytes)?;
        if v["error"].is_object() && v.get("integrity").is_none() {
            if v["error"]["request_id"]!=id {return Err("Error request mismatch".into());}
            return Err(text(&v["error"],"code")?.into());
        }
        if v["request_id"]!=id {return Err("Response request mismatch".into());}
        if !(200..300).contains(&status) && v.get("integrity").is_none() {return Err("HTTP failure".into());}
        // Exact-body retry may return the original signed response. Anchoring
        // to its first attempt prevents delayed delivery from buying more time.
        Ok((v,pending.started))
    }
    fn verified(&self,v:&Value) -> Result<VerifiedDocument> {
        let document=verify_signed(v,text(&self.binding.value["platform"],"authorization_public_key_id")?,&self.binding.key)?;
        equal(v,&self.binding.value["software"],&IDENTITY)?;
        Ok(document)
    }
    fn auth_result(&mut self,pending:&Pending) -> Result<()> {
        let (v,received)=self.exchange(pending)?;
        let document=self.verified(&v)?;
        if !self.binding.auth_validator.is_valid(&v) {return Err("Response schema invalid".into());}
        if v["contract_version"]!="authorization.v1" || (pending.action!="activate" && v["authorization_id"]!=pending.body["authorization_id"]) {return Err("Authorization correlation failed".into());}
        if matches!(v["decision"].as_str(),Some("active"|"grace"|"not_modified")) && (v["device_scope"]["installation_id"]!=self.installation || !v["device_scope"]["device_id"].is_string()) {return Err("Device correlation failed".into());}
        self.session.accept(document,received)?;
        self.publish_deadline();
        self.error=None;Ok(())
    }
    fn outcome(&mut self,result:Result<()>,pending:Pending) -> Result<()> {
        match result {
            Ok(())=>{self.pending=None;Ok(())},
            Err(error)=>{
                let retry=matches!(error.as_str(),"NETWORK_RETRY"|"RATE_LIMITED_RETRY"|"SERVER_RETRY");
                if retry {self.pending=Some(pending);} else {self.pending=None;self.session.invalidate();self.launch=None;self.publish_deadline();}
                self.error=Some(error.clone());Err(error)
            }
        }
    }
    pub fn activate(&mut self,credential:&str) -> Result<()> {
        if self.pending.is_some() {return Err("Retry the existing unknown request first".into());}
        if credential.trim().is_empty() || credential.chars().count()>256 {return Err("Invalid credential".into());}
        // Explicit new activation is the only way to start a new terminal scope.
        self.session=LiveSession::default();self.launch=None;self.launched=false;
        self.publish_deadline();
        let p=self.request("activate",Some(credential),None)?;
        let r=self.auth_result(&p);self.outcome(r,p)
    }
    pub fn verify(&mut self) -> Result<()> {
        if self.pending.is_some() {return self.retry();}
        let p=self.request("verify",None,None)?;let r=self.auth_result(&p);self.outcome(r,p)
    }
    pub fn deactivate(&mut self) -> Result<()> {
        if self.pending.is_some() {return Err("Resolve pending request before deactivation".into());}
        let p=self.request("deactivate",None,None)?;let r=self.auth_result(&p);self.outcome(r,p)
    }
    pub fn retry(&mut self) -> Result<()> {
        let Some(p)=self.pending.take() else {return self.verify()};
        let result=match p.action.as_str() {
            "launch-ticket"=>self.issue_result(&p).and_then(|ticket| self.consume_ticket(&ticket)),
            "ticket-consume"=>self.consume_result(&p),_=>self.auth_result(&p)
        };
        // consume_ticket owns its new pending consume request on failure.
        if self.pending.is_some() {return result;}
        self.outcome(result,p)
    }
    fn issue_result(&mut self,p:&Pending) -> Result<Value> {
        let (v,received)=self.exchange(p)?;self.verified(&v)?;
        let current=self.session.response().ok_or("No authorization")?;
        equal(&v,current,&["authorization_id","authorization_revision"])?;
        let ticket=&v["ticket"];
        if v["schema_version"]!="authorization.v1" || v["contract_version"]!="authorization.v1" || v["decision"]!="issued" {return Err("Invalid issued contract".into());}
        let audience=format!("{}-core",text(&self.binding.value["software"],"software_id")?);
        if v["integrity"]["origin"]!="authorization-platform" || v["integrity"]["audience"]!=audience || ticket["audience"]!=audience {return Err("Ticket audience mismatch".into());}
        equal(ticket,current,&["software_id","profile_id","client_id"])?;
        if ticket["installation_id"]!=self.installation {return Err("Ticket device mismatch".into());}
        let time=epoch(&v,"server_time")?;
        if time<self.session.highwater.ok_or("No trusted time")? || epoch(ticket,"issued_at")?>time || epoch(ticket,"not_before")?>time || epoch(ticket,"expires_at")?<=self.session.trusted_time(received).ok_or("No trusted time")?.max(time) || epoch(ticket,"expires_at")?>epoch(current,"expires_at")? {return Err("Ticket time invalid".into());}
        text(ticket,"ticket_id")?;
        self.session.accept_ticket_time(time,received);self.publish_deadline();Ok(v)
    }
    fn consume_result(&mut self,p:&Pending) -> Result<()> {
        let (v,received)=self.exchange(p)?;
        let keys=["schema_version","contract_version","request_id","software_id","profile_id","authorization_id","decision","server_time","ticket_id"];
        if v.as_object().map(|o|o.len())!=Some(keys.len()) || keys.iter().any(|k|v.get(*k).is_none()) || v["schema_version"]!="authorization.v1" || v["contract_version"]!="authorization.v1" || v["decision"]!="consumed" {return Err("Invalid consumed contract".into());}
        equal(&v,&p.body,&["software_id","profile_id","authorization_id","ticket_id"])?;
        if !self.session.usable(received) {return Err("Online success window ended before launch".into());}
        let time=epoch(&v,"server_time")?;
        let current=self.session.response().ok_or("No authorization")?;
        if time<self.session.highwater.ok_or("No trusted time")? || time>=epoch(current,"expires_at")? {return Err("Consumed time invalid".into());}
        let issued=p.issued.as_ref().ok_or("Missing issued ticket context")?;
        if current["authorization_revision"]!=issued["authorization_revision"] || time<epoch(issued,"server_time")? || time<epoch(&issued["ticket"],"not_before")? || time>=epoch(&issued["ticket"],"expires_at")? {return Err("Consumed ticket context expired".into());}
        self.session.accept_ticket_time(time,received);self.publish_deadline();
        if !self.session.usable(Instant::now()) {return Err("Online success window ended before launch".into());}
        let remaining=epoch(&issued["ticket"],"expires_at")?.saturating_sub(self.session.trusted_time(Instant::now()).ok_or("No trusted clock")?.max(time));
        if remaining<=0 {return Err("Ticket expired before launch".into());}
        self.launch=Some(LaunchPermit{ticket_id:text(&v,"ticket_id")?.into(),authorization_id:text(&v,"authorization_id")?.into(),deadline:Instant::now()+Duration::from_secs(remaining as u64)});
        self.error=None;Ok(())
    }
    fn consume_ticket(&mut self,issued:&Value) -> Result<()> {
        let mut p=self.request("ticket-consume",None,Some(text(&issued["ticket"],"ticket_id")?))?;
        p.issued=Some(issued.clone());
        let r=self.consume_result(&p);self.outcome(r,p)
    }
    pub fn request_launch(&mut self) -> Result<()> {
        if !self.session.usable(Instant::now()) || self.launched || self.pending.is_some() {return Err("Launch not permitted in current host state".into());}
        let p=self.request("launch-ticket",None,None)?;
        match self.issue_result(&p) {
            Ok(ticket)=>self.consume_ticket(&ticket),Err(e)=>self.outcome(Err(e),p)
        }
    }
    pub fn take_launch_permit(&mut self) -> Option<LaunchPermit> {
        if !self.session.usable(Instant::now()) {self.launch=None;return None;}
        let permit=self.launch.take()?;
        if !self.permit_still_valid(&permit) {return None;}
        self.launched=true;Some(permit)
    }
    pub fn permit_still_valid(&self,permit:&LaunchPermit)->bool {
        self.usable() && Instant::now()<permit.deadline && self.session.response().map(|v|v["authorization_id"]==permit.authorization_id).unwrap_or(false)
    }
    pub fn tick(&mut self) {
        if self.session.due(Instant::now()) {let _=self.verify();}
        if !self.session.usable(Instant::now()) {self.launch=None;}
    }
    pub fn usable(&self) -> bool {self.session.usable(Instant::now())}
    pub fn deadline(&self) -> Option<Instant> {self.session.deadline()}
    pub fn timing_receipt(&self) -> Value {
        json!({"trusted_time":self.session.trusted_time(Instant::now()),"response":self.session.response().map(|v|json!({"server_time":v["server_time"],"next_verify_at":v["next_verify_at"],"expires_at":v["expires_at"],"decision":v["decision"]})),"usable":self.usable()})
    }
    pub fn local_public_key(&self) -> String {URL_SAFE_NO_PAD.encode(self.local.verifying_key().to_bytes())}
    pub fn local_envelope(&self) -> Result<Value> {
        let now=Instant::now();let mut v=self.session.response().ok_or("No verified authorization")?.clone();
        for field in TIMES {if epoch(&v,field)?<0 {return Err("Negative local epoch denied".into());}}
        v["schema_version"]="authorization-a-core.v1".into();v["local_contract_version"]="authorization-a-core.v1".into();v["contract_version"]="authorization-a-core.v1".into();
        v["request_id"]=random_id().into();v["server_time"]=self.session.trusted_time(now).ok_or("No trusted clock")?.into();
        v["decision"]=self.session.decision.as_deref().ok_or("No authorization decision")?.into();
        if !self.session.usable(now) {v["decision"]="blocked".into();v["state_code"]="ONLINE_WINDOW_ENDED".into();}
        v["integrity"]=json!({"origin":"authorization-a","audience":"authorization-a-core","algorithm":"ed25519","key_id":"local-session","canonicalization":"JCS-RFC8785"});
        let signed=sign(v,&self.local)?;if !self.binding.local_validator.is_valid(&signed){return Err("Local response schema invalid".into());}Ok(signed)
    }
    /// Single authoritative snapshot for host permissions and the page.
    pub fn snapshot(&self) -> Value {
        let usable=self.session.usable(Instant::now());
        let response=self.session.response();
        let decision=if usable {"active"} else if self.error.is_some() {"unavailable"} else if response.is_some() {"blocked"} else {"unauthenticated"};
        let mut intents=Vec::new();
        if usable && !self.launched && self.pending.is_none() {intents.push("request_launch");}
        if self.pending.is_some() || (!usable && response.is_some()) {intents.push("retry");}
        if !usable && self.pending.is_none() {intents.push("activate");}
        let mut modules=Vec::new();let mut enabled=Vec::new();
        if let Some(v)=response {
            let support=&v["modules"]["contact"];
            let fields:Map<String,Value>=["qq","wechat"].into_iter().filter_map(|k|support[k].as_str().filter(|s|!s.trim().is_empty()).map(|s|(k.into(),s.into()))).collect();
            if !fields.is_empty() {modules.push(json!({"kind":"contact","module_id":"platform-contact","fields":fields}));enabled.push("contact");}
            if let Some(url)=support["purchase_url"].as_str().filter(|s|s.starts_with("https://") || s.starts_with("http://")) {modules.push(json!({"kind":"purchase","module_id":"platform-purchase","fields":{"url":url}}));enabled.push("purchase");}
            let notice=&v["modules"]["notice"];
            let fields:Map<String,Value>=["title","body"].into_iter().filter_map(|k|notice[k].as_str().filter(|s|!s.trim().is_empty()).map(|s|(k.into(),s.into()))).collect();
            if !fields.is_empty() {modules.push(json!({"kind":"notice","module_id":"platform-notice","fields":fields}));enabled.push("notice");}
        }
        json!({"profile":{"locale":"zh-CN","theme":{"accent":"#D4B45A","surface":"#0C0B09","text":"#F3EEE4","danger":"#E85A6F"},"copy":{},"enabled_modules":enabled},
            "snapshot":{"schema_version":"authorization-a-ui.v1","product_id":self.binding.value["software"]["software_id"],"profile_id":self.binding.value["software"]["profile_id"],
            "display_name":self.binding.value["software"]["name"],"device_code":response.and_then(|v| v["device_scope"]["installation_id"].as_str()).map(compact_device_code).map(Value::String),"modules":modules,
            "expires_at":response.map(|v|v["expires_at"].clone()),"authorization_revision":response.map(|v|v["authorization_revision"].clone()),"error":self.error,
            "state":{"screen":if usable {"status"} else {"login"},"authorization":decision,"connectivity":if self.error.as_deref()==Some("NETWORK_RETRY") {"offline"} else {"online"},"source":if response.is_some() {"live"} else {"none"},"intents":intents}}})
    }
    /// Bridge and acceptance commands share this exact permission gate.
    pub fn dispatch(&mut self,command:&Value) -> Result<()> {
        let snapshot=self.snapshot();
        if command["type"]=="open_module" {
            let module=text(command,"module")?;
            if !snapshot["profile"]["enabled_modules"].as_array().unwrap().iter().any(|v|v==module) {return Err("Empty or disabled channel".into());}
            if module=="purchase" {
                let url=self.session.response().ok_or("No verified channel")?["modules"]["contact"]["purchase_url"].as_str().ok_or("No purchase URL")?;
                let parsed=url::Url::parse(url).map_err(|_|"Invalid purchase URL")?;
                if !matches!(parsed.scheme(),"https"|"http") || parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {return Err("Invalid purchase URL".into());}
                #[cfg(windows)] unsafe {
                    #[link(name="shell32")] unsafe extern "system" {fn ShellExecuteW(window:*mut std::ffi::c_void,verb:*const u16,file:*const u16,params:*const u16,dir:*const u16,show:i32)->isize;}
                    let wide:Vec<u16>=url.encode_utf16().chain(Some(0)).collect();
                    if ShellExecuteW(std::ptr::null_mut(),std::ptr::null(),wide.as_ptr(),std::ptr::null(),std::ptr::null(),1)<=32 {return Err("Could not open purchase channel".into());}
                }
            }
            return Ok(());
        }
        let name=if command["type"]=="activate" {"activate"} else {text(command,"name")?};
        if !snapshot["snapshot"]["state"]["intents"].as_array().unwrap().iter().any(|v|v==name) {return Err("Intent denied by current host snapshot".into());}
        match name {"activate"=>self.activate(text(command,"credential")?),"retry"=>self.retry(),"request_launch"=>self.request_launch(),_=>Err("Unknown host intent".into())}
    }
}

/// The key is protected by Windows DPAPI for this user's account and software
/// scope. There is no plaintext seed or card file and no browser storage.
#[cfg(windows)]
pub fn device_key(path:&Path, scope:&str) -> Result<SigningKey> {
    #[repr(C)] struct Blob {len:u32, data:*mut u8}
    #[link(name="crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(input:*const Blob,description:*const u16,entropy:*const Blob,reserved:*mut std::ffi::c_void,prompt:*mut std::ffi::c_void,flags:u32,output:*mut Blob)->i32;
        fn CryptUnprotectData(input:*const Blob,description:*mut *mut u16,entropy:*const Blob,reserved:*mut std::ffi::c_void,prompt:*mut std::ffi::c_void,flags:u32,output:*mut Blob)->i32;
    }
    #[link(name="kernel32")]
    unsafe extern "system" {fn LocalFree(memory:*mut std::ffi::c_void)->*mut std::ffi::c_void;}
    let entropy=Blob{len:scope.len() as u32,data:scope.as_ptr() as *mut u8};
    let protect=|bytes:&[u8],encrypt:bool| -> Result<Vec<u8>> {
        let input=Blob{len:bytes.len() as u32,data:bytes.as_ptr() as *mut u8};
        let mut output=Blob{len:0,data:std::ptr::null_mut()};
        let ok=unsafe {if encrypt {CryptProtectData(&input,std::ptr::null(),&entropy,std::ptr::null_mut(),std::ptr::null_mut(),1,&mut output)}
            else {CryptUnprotectData(&input,std::ptr::null_mut(),&entropy,std::ptr::null_mut(),std::ptr::null_mut(),1,&mut output)}};
        if ok==0 {return Err("Device key secure storage unavailable".into());}
        let out=unsafe {std::slice::from_raw_parts(output.data,output.len as usize).to_vec()};
        unsafe {LocalFree(output.data.cast());}Ok(out)
    };
    let mut seed=if path.exists() {
        let raw=fs::read(path).map_err(|_| "Device key read failed")?;
        if raw.len()>8192 {return Err("Invalid protected key size".into());}
        protect(&raw,false)?
    } else {
        let key=SigningKey::generate(&mut OsRng);let seed=key.to_bytes();
        let encrypted=protect(&seed,true)?;
        if let Some(parent)=path.parent() {fs::create_dir_all(parent).map_err(|_| "Key directory unavailable")?;}
        let mut file=fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|_| "Device key exists or cannot be created")?;
        file.write_all(&encrypted).and_then(|_|file.sync_all()).map_err(|_| "Protected key write failed")?;
        seed.to_vec()
    };
    let result=seed.as_slice().try_into().map(|bytes:&[u8;32]|SigningKey::from_bytes(bytes)).map_err(|_| "Invalid protected device key".into());
    seed.fill(0);result
}
#[cfg(not(windows))]
pub fn device_key(_path:&Path,_scope:&str) -> Result<SigningKey> {Err("Configure OS secure device storage for this target".into())}

pub struct LocalEndpoint {pub address:String,pub bootstrap_token:String,pub public_key:String}
/// A real loopback channel. Bootstrap material is delivered to the child via
/// its environment, never a URL, log, or browser. Core implementation must pin
/// this key and enforce each protected function itself (target-specific).
pub fn serve_local(host:std::sync::Arc<std::sync::Mutex<DesktopHost>>) -> Result<LocalEndpoint> {
    use std::net::{TcpListener,TcpStream};
    let listener=TcpListener::bind("127.0.0.1:0").map_err(|_| "Local bind failed")?;
    let address=format!("http://{}/local/v1",listener.local_addr().map_err(|_| "Local address unavailable")?);
    let bootstrap_token=random_id();let bootstrap=bootstrap_token.clone();
    let public_key=host.lock().map_err(|_| "Host unavailable")?.local_public_key();
    std::thread::spawn(move || {
        let mut sessions=HashSet::<String>::new();let mut nonces=HashSet::<String>::new();
        for stream in listener.incoming() {
            let Ok(mut stream)=stream else {break};
            let _=stream.set_read_timeout(Some(Duration::from_secs(2)));let _=stream.set_write_timeout(Some(Duration::from_secs(2)));
            fn read(stream:&mut TcpStream)->Result<(String,String,String,Value)> {
                let mut header=Vec::new();let mut byte=[0];
                while !header.ends_with(b"\r\n\r\n") {
                    if header.len()>8192 || stream.read(&mut byte).map_err(|_| "Local read")?!=1 {return Err("Invalid local headers".into());}
                    header.push(byte[0]);
                }
                let header=String::from_utf8(header).map_err(|_| "Local UTF-8")?;
                let mut lines=header.split("\r\n");let mut first=lines.next().ok_or("Local request")?.split_whitespace();
                let method=first.next().ok_or("Local method")?.to_string();let path=first.next().ok_or("Local path")?.to_string();
                let mut token=String::new();let mut length=0;let mut seen=HashSet::new();
                for line in lines.filter(|s|!s.is_empty()) {
                    let (key,value)=line.split_once(':').ok_or("Local header")?;let key=key.to_ascii_lowercase();
                    if !seen.insert(key.clone()) {return Err("Duplicate local header".into());}
                    if key=="authorization" {token=value.trim().strip_prefix("Bearer ").unwrap_or("").to_string();}
                    if key=="transfer-encoding" {return Err("Local chunked unsupported".into());}
                    if key=="content-length" {length=value.trim().parse::<usize>().map_err(|_| "Local length")?;}
                }
                if length>16384 {return Err("Local body limit".into());}
                let mut body=vec![0;length];stream.read_exact(&mut body).map_err(|_| "Local body")?;
                Ok((method,path,token,if length==0 {Value::Null} else {parse_json(&body)?}))
            }
            let result=read(&mut stream).and_then(|(method,path,token,body)| {
                let mut host=host.lock().map_err(|_| "Host unavailable")?;
                if path=="/local/v1/session/open" && method=="POST" {
                    if token!=bootstrap || !host.usable() {return Err("Local bootstrap denied".into());}
                    equal(&body,&host.binding.value["software"],&["software_id","profile_id","client_id"])?;
                    if body["client_version"]!=host.binding.version {return Err("Core version mismatch".into());}
                    let nonce=text(&body,"nonce")?.to_string();
                    if nonce.len()<16 || nonces.len()>=4096 || !nonces.insert(nonce) {return Err("Local nonce rejected".into());}
                    let session=random_id();sessions.insert(session.clone());
                    return Ok(json!({"session_token":session,"response":host.local_envelope()?}));
                }
                if !sessions.contains(&token) {return Err("Local session denied".into());}
                match (method.as_str(),path.as_str()) {
                    ("GET","/local/v1/health")=>Ok(json!({"local_contract_version":"authorization-a-core.v1","software_id":host.binding.value["software"]["software_id"],"profile_id":host.binding.value["software"]["profile_id"],"ready":host.usable()})),
                    ("GET","/local/v1/session/state")=>host.local_envelope(),
                    ("POST","/local/v1/session/refresh")=>{let _=host.verify();host.local_envelope()},
                    ("POST","/local/v1/session/close")=>{sessions.remove(&token);Ok(json!({"closed":true}))},
                    _=>Err("Unknown local route".into())
                }
            });
            let (status,value)=match result {Ok(v)=>(200,v),Err(_)=>(403,json!({"error":{"code":"LOCAL_DENIED"}}))};
            let body=serde_json::to_vec(&value).unwrap();
            let _=write!(stream,"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",body.len());
            let _=stream.write_all(&body);
        }
    });
    Ok(LocalEndpoint{address,bootstrap_token,public_key})
}
