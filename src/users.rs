//! # Firebase Auth API - User information
//!
//! Retrieve firebase user information

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::errors::{extract_google_api_error, Result};
use super::sessions::{service_account, user};
use crate::errors::FirebaseError;
use crate::FirebaseAuthBearer;

/// A federated services like Facebook, Github etc that the user has used to
/// authenticated himself and that he associated with this firebase auth account.
#[allow(non_snake_case)]
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ProviderUserInfo {
    pub providerId: String,
    pub federatedId: String,
    pub displayName: Option<String>,
    pub photoUrl: Option<String>,
}

/// Users id, email, display name and a few more information
#[allow(non_snake_case)]
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct FirebaseAuthUser {
    pub localId: Option<String>,
    pub email: Option<String>,
    /// True if the user has verified his email address
    pub emailVerified: Option<bool>,
    pub displayName: Option<String>,
    /// Find all federated services like Facebook, Github etc that the user has used to
    /// authenticated himself and that he associated with this firebase auth account.
    pub providerUserInfo: Option<Vec<ProviderUserInfo>>,
    pub photoUrl: Option<String>,
    /// True if the account is disabled. A disabled account cannot login anymore.
    pub disabled: Option<bool>,
    /// Last login datetime in UTC
    pub lastLoginAt: Option<String>,
    /// Created datetime in UTC
    pub createdAt: Option<String>,
    /// Serialized JSON with custom JWT claims
    pub customAttributes: Option<String>,
}

impl FirebaseAuthUser {
    pub fn custom_claims<T: DeserializeOwned + Default>(&self) -> Result<T> {
        let attr = self.customAttributes.clone();
        match attr {
            Some(s) => Ok(serde_json::from_str(&s)?),
            None => Ok(T::default()),
        }
    }
}

/// Your user information query might return zero, one or more [`FirebaseAuthUser`] structures.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct FirebaseAuthUserResponse {
    pub users: Vec<FirebaseAuthUser>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Debug)]
pub struct UserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idToken: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phoneNumber: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Default, Clone, Debug)]
struct UserUpdateRequest {
    localId: String,
    returnSecureToken: bool,
    #[serde(flatten)]
    data: HashMap<String, String>,
}

impl UserUpdateRequest {
    const MAX_CUSTOM_CLAIM_PAYLOAD: usize = 1000;

    fn new(user_id: &str) -> Self {
        UserUpdateRequest {
            returnSecureToken: true,
            localId: user_id.to_string(),
            data: HashMap::new(),
        }
    }

    fn update_custom_claims<T: Serialize>(&mut self, claims: T) -> Result<Self> {
        let serialized = serde_json::to_string(&claims)?;

        if serialized.len() > Self::MAX_CUSTOM_CLAIM_PAYLOAD {
            return Err(FirebaseError::Generic("claim exceeded max payload length"));
        }

        let deserialized: HashMap<&str, Value> = serde_json::de::from_str(&serialized)?;
        for &name in reserved_claims().iter() {
            if deserialized.contains_key(name) {
                return Err(FirebaseError::Generic(
                    "claim is reserved and must not be set",
                ));
            }
        }

        self.data.insert("customAttributes".to_string(), serialized);
        Ok(self.to_owned())
    }
}

#[inline]
fn firebase_auth_url(action: &str, key: &str) -> String {
    format!(
        "https://identitytoolkit.googleapis.com/v1/accounts:{}?key={}",
        action, key
    )
}

#[inline]
fn firebase_auth_project_url(action: &str, project: &str, key: &str) -> String {
    format!(
        "https://identitytoolkit.googleapis.com/v1/projects/{}/accounts:{}?key={}",
        project, action, key
    )
}

#[inline]
fn reserved_claims() -> [&'static str; 16] {
    [
        "acr",
        "amr",
        "at_hash",
        "aud",
        "auth_time",
        "azp",
        "cnf",
        "c_hash",
        "exp",
        "firebase",
        "iat",
        "iss",
        "jti",
        "nbf",
        "nonce",
        "sub",
    ]
}

/// Retrieve information about the firebase auth user associated with the given user session
///
/// Error codes:
/// - INVALID_ID_TOKEN
/// - USER_NOT_FOUND
pub fn user_info(session: &user::Session) -> Result<FirebaseAuthUserResponse> {
    let url = firebase_auth_url("lookup", &session.api_key);

    let resp = session
        .client()
        .post(&url)
        .json(&UserRequest {
            idToken: Some(session.access_token()),
            uid: None,
            email: None,
            phoneNumber: None,
        })
        .send()?;

    let resp = extract_google_api_error(resp, || session.user_id.to_owned())?;

    Ok(resp.json()?)
}

/// Retrieve information about the firebase auth user associated with the given uid
///
/// Error codes:
/// - INVALID_ID_TOKEN
/// - USER_NOT_FOUND
pub fn get_user(session: &service_account::Session, uid: &str) -> Result<FirebaseAuthUser> {
    get_user_info(
        session,
        UserRequest {
            idToken: None,
            uid: Some(uid.to_string()),
            email: None,
            phoneNumber: None,
        },
    )
}

/// Retrieve information about the firebase auth user associated with the given email
///
/// Error codes:
/// - INVALID_ID_TOKEN
/// - USER_NOT_FOUND
pub fn get_user_by_email(
    session: &service_account::Session,
    email: &str,
) -> Result<FirebaseAuthUser> {
    get_user_info(
        session,
        UserRequest {
            idToken: None,
            email: Some(email.to_string()),
            uid: None,
            phoneNumber: None,
        },
    )
}

/// Retrieve information about the firebase auth user associated with the given email
///
/// Error codes:
/// - INVALID_ID_TOKEN
/// - USER_NOT_FOUND
pub fn get_user_by_phone(
    session: &service_account::Session,
    phone: &str,
) -> Result<FirebaseAuthUser> {
    get_user_info(
        session,
        UserRequest {
            idToken: None,
            email: None,
            uid: None,
            phoneNumber: Some(phone.to_string()),
        },
    )
}

fn get_user_info(
    session: &service_account::Session,
    request: UserRequest,
) -> Result<FirebaseAuthUser> {
    let url = firebase_auth_url("lookup", &session.credentials.api_key);

    let resp = session
        .client()
        .post(&url)
        .bearer_auth(session.oauth_access_token().to_owned())
        .json(&request)
        .send()?;

    let resp = extract_google_api_error(resp, || format!("{:?}", request))?;
    let result: FirebaseAuthUserResponse = resp.json()?;
    match result.users.first() {
        Some(user) => Ok(user.clone()),
        None => Err(FirebaseError::Generic("empty result")),
    }
}

/// Updates the firebase auth user data associated with the given user session
///
/// Error codes:
/// - INVALID_ID_TOKEN
/// - USER_NOT_FOUND
pub fn user_set_claims<T: Serialize>(
    session: &service_account::Session,
    user_id: &str,
    claims: T,
) -> Result<()> {
    let req = UserUpdateRequest::new(user_id.clone()).update_custom_claims(claims)?;

    let url = firebase_auth_project_url(
        "update",
        &session.credentials.project_id,
        &session.credentials.api_key,
    );
    let resp = session
        .client()
        .post(&url)
        .bearer_auth(session.oauth_access_token().to_owned())
        .json(&req)
        .send()?;

    extract_google_api_error(resp, || user_id.to_owned())?;
    Ok({})
}

/// Removes the firebase auth user associated with the given user session
///
/// Error codes:
/// - INVALID_ID_TOKEN
/// - USER_NOT_FOUND
pub fn user_remove(session: &user::Session) -> Result<()> {
    let url = firebase_auth_url("delete", &session.api_key);
    let resp = session
        .client()
        .post(&url)
        .json(&UserRequest {
            idToken: Some(session.access_token()),
            uid: None,
            email: None,
            phoneNumber: None,
        })
        .send()?;

    extract_google_api_error(resp, || session.user_id.to_owned())?;
    Ok({})
}

#[allow(non_snake_case)]
#[derive(Default, Deserialize)]
struct SignInUpUserResponse {
    localId: Option<String>,
    idToken: String,
    refreshToken: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SignInUpUserRequest {
    pub email: String,
    pub password: String,
    pub returnSecureToken: bool,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SignInCustom {
    pub token: String,
    pub returnSecureToken: bool,
}

fn sign_up_in(
    session: &service_account::Session,
    email: &str,
    password: &str,
    action: &str,
) -> Result<user::Session> {
    let url = firebase_auth_url(action, &session.credentials.api_key);
    let resp = session
        .client()
        .post(&url)
        .json(&SignInUpUserRequest {
            email: email.to_owned(),
            password: password.to_owned(),
            returnSecureToken: true,
        })
        .send()?;

    let resp = extract_google_api_error(resp, || email.to_owned())?;

    let resp: SignInUpUserResponse = resp.json()?;

    Ok(user::Session::new(
        &session.credentials,
        resp.localId.as_deref(),
        Some(&resp.idToken),
        Some(&resp.refreshToken),
    )?)
}

/// Creates the firebase auth user with the given email and password and returns
/// a user session.
///
/// Error codes:
/// EMAIL_EXISTS: The email address is already in use by another account.
/// OPERATION_NOT_ALLOWED: Password sign-in is disabled for this project.
/// TOO_MANY_ATTEMPTS_TRY_LATER: We have blocked all requests from this device due to unusual activity. Try again later.
pub fn sign_up(
    session: &service_account::Session,
    email: &str,
    password: &str,
) -> Result<user::Session> {
    sign_up_in(session, email, password, "signUp")
}

/// Signs in with the given email and password and returns a user session.
///
/// Error codes:
/// EMAIL_NOT_FOUND: There is no user record corresponding to this identifier. The user may have been deleted.
/// INVALID_PASSWORD: The password is invalid or the user does not have a password.
/// USER_DISABLED: The user account has been disabled by an administrator.
pub fn sign_in(
    session: &service_account::Session,
    email: &str,
    password: &str,
) -> Result<user::Session> {
    sign_up_in(session, email, password, "signInWithPassword")
}

/// Signs in with the given custom JWT and returns a user session.
///
/// Error codes:
/// EMAIL_NOT_FOUND: There is no user record corresponding to this identifier. The user may have been deleted.
/// INVALID_PASSWORD: The password is invalid or the user does not have a password.
/// USER_DISABLED: The user account has been disabled by an administrator.
pub fn sign_in_with_custom_jwt(
    session: &service_account::Session,
    user_id: &str,
    token: &str,
) -> Result<user::Session> {
    let url = firebase_auth_url("signInWithCustomToken", &session.credentials.api_key);
    let resp = session
        .client()
        .post(&url)
        .json(&SignInCustom {
            token: token.to_owned(),
            returnSecureToken: true,
        })
        .send()?;

    let resp = extract_google_api_error(resp, || "signInWithCustomToken".to_owned())?;

    let resp: SignInUpUserResponse = resp.json()?;
    let mut session = user::Session::by_access_token(&session.credentials, &resp.idToken)?;
    session.user_id = user_id.to_string();
    Ok(session)
}
