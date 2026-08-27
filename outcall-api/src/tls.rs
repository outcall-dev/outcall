use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const INTERCEPT_LEAF_TTL_SECS_DEFAULT: u64 = 86_400;
pub const INTERCEPT_BODY_CAP_BYTES_DEFAULT: usize = 1_048_576;
pub const INTERCEPT_LEAF_CACHE_MAX: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    Proxy,
    DirectIp,
    Intercept,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptConfig {
    pub leaf_ttl_secs: u64,
    pub body_cap_bytes: usize,
    pub match_body: bool,
}

#[derive(Debug, Clone)]
pub struct InterceptedRequestContext {
    pub hostname: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body_size: usize,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaStatus {
    pub loaded: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub subject_serial: Option<String>,
    pub interception_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaBundleResult {
    pub pem_bundle: String,
}
