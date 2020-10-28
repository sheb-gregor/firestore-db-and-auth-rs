use serde::Deserialize;

pub const GOOGLE_OAUTH_URL: &'static str = "https://accounts.google.com/o/oauth2/token";
pub static JWT_AUDIENCE_OAUTH: &'static str =
    "https://accounts.google.com/o/oauth2/token";

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

pub fn service_scope_list() -> [String; 8] {
    [
        "https://www.googleapis.com/auth/cloud-platform".to_string(),
        "https://www.googleapis.com/auth/datastore".to_string(),
        "https://www.googleapis.com/auth/devstorage.full_control".to_string(),
        "https://www.googleapis.com/auth/firebase".to_string(),
        "https://www.googleapis.com/auth/firebase.database".to_string(),
        "https://www.googleapis.com/auth/firebase.messaging".to_string(),
        "https://www.googleapis.com/auth/identitytoolkit".to_string(),
        "https://www.googleapis.com/auth/userinfo.email".to_string(),
    ]
}

pub fn user_scope_list() -> [String; 5] {
    [
        "https://www.googleapis.com/auth/cloud-platform".to_string(),
        "https://www.googleapis.com/auth/firebase.database".to_string(),
        "https://www.googleapis.com/auth/firebase.messaging".to_string(),
        "https://www.googleapis.com/auth/identitytoolkit".to_string(),
        "https://www.googleapis.com/auth/userinfo.email".to_string(),
    ]
}

pub fn request_form(assertion: String) -> [(&'static str, String); 2] {
    [("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()), ("assertion", assertion)]
}

