use base64::Engine;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum Action {
    #[serde(rename = "NOERROR")]
    NoError,
    #[serde(rename = "FORMERR")]
    FormErr,
    #[serde(rename = "SERVFAIL")]
    ServFail,
    #[serde(rename = "NXDOMAIN")]
    NXDomain,
    #[serde(rename = "NOTIMP")]
    NotImp,
    #[serde(rename = "REFUSED")]
    Refused,
    #[serde(rename = "YXDOMAIN")]
    YXDomain,
    #[serde(rename = "YXRRSET")]
    YXRRSet,
    #[serde(rename = "NXRRSET")]
    NXRRSet,
    #[serde(rename = "NOTAUTH")]
    NotAuth,
    #[serde(rename = "NOTZONE")]
    NotZone,
    #[serde(rename = "BIFROST_BLOCK")]
    BifrostBlock,
    #[serde(rename = "BIFROST_ALLOW")]
    BifrostAllow,
    #[serde(rename = "BIFROST_RW")]
    BifrostRW,
    #[serde(rename = "BIFROST_CACHE")]
    BifrostCache,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseRecord {
    pub rtype: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub client_ip: String,
    pub domain: String,
    pub qtype: u16,
    pub action: Action,
    pub client_rcode: Action,
    pub ede_code: Option<u16>,
    pub list_id: Option<String>,
    pub latency_us: Option<i32>,
    pub queried_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_records: Option<Vec<ResponseRecord>>,
}

impl QueryEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_ip: String,
        domain: String,
        qtype: u16,
        action: Action,
        client_rcode: Action,
        ede_code: Option<u16>,
        list_id: Option<String>,
        latency_us: Option<i32>,
        response_records: Option<Vec<ResponseRecord>>,
    ) -> Self {
        Self {
            event_type: "query_event".to_string(),
            client_ip,
            domain,
            qtype,
            action,
            client_rcode,
            ede_code,
            list_id,
            latency_us,
            queried_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            response_records,
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheStore {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub domain: String,
    pub qtype: u16,
    pub response: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

impl CacheStore {
    pub fn new(domain: String, qtype: u16, response: Vec<u8>, ttl: u32) -> Self {
        Self {
            msg_type: "cache_store".to_string(),
            domain,
            qtype,
            response: base64::engine::general_purpose::STANDARD.encode(&response),
            ttl,
            fingerprint: None,
            expires_at_ms: None,
            variant: None,
        }
    }

    pub fn tagged(mut self, fingerprint: String, variant: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.expires_at_ms = Some(now.saturating_add(self.ttl as u64 * 1000));
        self.fingerprint = Some(fingerprint);
        self.variant = Some(variant);
        self
    }

    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_serializes_to_expected_strings() {
        assert_eq!(serde_json::to_value(Action::NoError).unwrap(), "NOERROR");
        assert_eq!(serde_json::to_value(Action::ServFail).unwrap(), "SERVFAIL");
        assert_eq!(serde_json::to_value(Action::NXDomain).unwrap(), "NXDOMAIN");
        assert_eq!(serde_json::to_value(Action::Refused).unwrap(), "REFUSED");
        assert_eq!(
            serde_json::to_value(Action::BifrostBlock).unwrap(),
            "BIFROST_BLOCK"
        );
        assert_eq!(
            serde_json::to_value(Action::BifrostCache).unwrap(),
            "BIFROST_CACHE"
        );
        assert_eq!(serde_json::to_value(Action::Unknown).unwrap(), "UNKNOWN");
    }

    #[test]
    fn query_event_serializes_to_expected_json() {
        let event = QueryEvent::new(
            "192.168.1.42".into(),
            "example.com".into(),
            1,
            Action::BifrostBlock,
            Action::NXDomain,
            Some(15),
            Some("hagezi-pro".into()),
            None,
            None,
        );
        let json: serde_json::Value = serde_json::from_slice(&event.to_json().unwrap()).unwrap();
        assert_eq!(json["type"], "query_event");
        assert_eq!(json["client_ip"], "192.168.1.42");
        assert_eq!(json["domain"], "example.com");
        assert_eq!(json["qtype"], 1);
        assert_eq!(json["action"], "BIFROST_BLOCK");
        assert_eq!(json["client_rcode"], "NXDOMAIN");
        assert_eq!(json["ede_code"], 15);
        assert_eq!(json["list_id"], "hagezi-pro");
        assert_eq!(json["latency_us"], serde_json::Value::Null);
        assert!(json["queried_at"].as_u64().is_some());
    }

    #[test]
    fn query_event_with_cache_hit_serializes() {
        let event = QueryEvent::new(
            "10.0.0.5".into(),
            "github.com".into(),
            28,
            Action::BifrostCache,
            Action::NoError,
            None,
            None,
            None,
            None,
        );
        let json: serde_json::Value = serde_json::from_slice(&event.to_json().unwrap()).unwrap();
        assert_eq!(json["type"], "query_event");
        assert_eq!(json["action"], "BIFROST_CACHE");
        assert_eq!(json["client_rcode"], "NOERROR");
        assert!(json["ede_code"].is_null());
        assert!(json["list_id"].is_null());
        assert!(json["latency_us"].is_null());
    }

    #[test]
    fn cache_store_serializes_with_base64_response() {
        let store = CacheStore::new("example.com".into(), 1, vec![0, 1, 2, 3, 255], 300);
        let json: serde_json::Value = serde_json::from_slice(&store.to_json().unwrap()).unwrap();
        assert_eq!(json["type"], "cache_store");
        assert_eq!(json["domain"], "example.com");
        assert_eq!(json["qtype"], 1);
        assert_eq!(
            json["response"],
            base64::engine::general_purpose::STANDARD.encode([0, 1, 2, 3, 255])
        );
        assert_eq!(json["ttl"], 300);
    }

    #[test]
    fn cache_store_base64_round_trip() {
        let original = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let store = CacheStore::new("test.example".into(), 1, original.clone(), 60);
        let json: serde_json::Value = serde_json::from_slice(&store.to_json().unwrap()).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(json["response"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn query_event_timestamp_is_set() {
        let event = QueryEvent::new(
            "1.2.3.4".into(),
            "test.com".into(),
            1,
            Action::NoError,
            Action::NoError,
            None,
            None,
            Some(1234),
            None,
        );
        let json: serde_json::Value = serde_json::from_slice(&event.to_json().unwrap()).unwrap();
        let ts = json["queried_at"].as_u64().unwrap();
        // Timestamp should be recent (within 10 seconds)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(ts <= now);
        assert!(ts > now - 10);
        assert_eq!(json["latency_us"], 1234);
    }
}
