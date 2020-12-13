//! # Firebase Auth API - User information
//!
//! Retrieve firebase user information

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::FirebaseError;
use crate::{Credentials, FirebaseAuthBearer};

use super::errors::{extract_google_api_error, Result};
use super::sessions::{service_account, user};
use chrono::format::Fixed::UpperAmPm;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requestType: Option<String>,
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

    fn update_email(&mut self, new_email: &str) -> Result<Self> {
        self.data.insert("email".to_string(), new_email.to_owned());
        Ok(self.to_owned())
    }

    fn update_password(&mut self, new_password: &str) -> Result<Self> {
        self.data
            .insert("password".to_string(), new_password.to_owned());

        Ok(self.to_owned())
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

pub(crate) fn auth_host() -> String {
    match std::env::var("FIREBASE_AUTH_EMULATOR_HOST") {
        Ok(v) => format!("http://{}/identitytoolkit.googleapis.com", v),
        Err(_) => "https://identitytoolkit.googleapis.com".to_string(),
    }
}

#[inline]
fn firebase_auth_url(action: &str, key: &str) -> String {
    format!("{}/v1/accounts:{}?key={}", auth_host(), action, key)
}

#[inline]
fn firebase_auth_project_url(action: &str, project: &str, key: &str) -> String {
    format!(
        "{}/v1/projects/{}/accounts:{}?key={}",
        auth_host(),
        project,
        action,
        key
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
            requestType: None,
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
            requestType: None,
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
            requestType: None,
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
            requestType: None,
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
            requestType: None,
        })
        .send()?;

    extract_google_api_error(resp, || session.user_id.to_owned())?;
    Ok({})
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

/// Specifies the required continue/state URL with optional Android and iOS settings. Used when
/// invoking the email action link generation APIs.
#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct ActionCodeSettings {
    pub continueUrl: String,
    pub canHandleCodeInApp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iOSBundleId: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub androidPackageName: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub androidMinimumVersion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub androidInstallApp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamicLinkDomain: Option<String>,
}

/// Signs in using an email and sign-in email link.
///
/// Error codes:
/// EMAIL_NOT_FOUND: There is no user record corresponding to this identifier. The user may have been deleted.
/// USER_DISABLED: The user account has been disabled by an administrator.
pub fn sign_in_with_email_link(
    session: &service_account::Session,
    email: &str,
    oob_code: &str,
) -> Result<user::Session> {
    let url = firebase_auth_url("emailLinkSignin", &session.credentials.api_key);
    #[allow(non_snake_case)]
    #[derive(Serialize)]
    struct Req {
        oobCode: String,
        email: String,
        returnSecureToken: bool,
    }
    let resp = session
        .client()
        .post(&url)
        .json(&Req {
            email: email.to_owned(),
            oobCode: oob_code.to_owned(),
            returnSecureToken: true,
        })
        .send()?;

    let resp = extract_google_api_error(resp, || "emailLinkSignin".to_owned())?;
    let resp: SignInUpUserResponse = resp.json()?;

    let session = user::Session::by_access_token(&session.credentials, &resp.idToken)?;
    Ok(session)
}

pub struct ManageUser {}

impl ManageUser {
    pub fn change_password(
        session: &service_account::Session,
        user_id: &str,
        new_password: &str,
    ) -> Result<()> {
        let req = UserUpdateRequest::new(user_id.clone()).update_password(new_password)?;

        Self::update_user(session, user_id, req)
    }

    pub fn change_email(
        session: &service_account::Session,
        user_id: &str,
        new_email: &str,
    ) -> Result<()> {
        let req = UserUpdateRequest::new(user_id.clone()).update_email(new_email)?;

        Self::update_user(session, user_id, req)
    }

    fn update_user(
        session: &service_account::Session,
        user_id: &str,
        req: UserUpdateRequest,
    ) -> Result<()> {
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

    pub fn send_reset_password_email(
        session: &service_account::Session,
        user_email: &str,
    ) -> Result<()> {
        let url = firebase_auth_project_url(
            "sendOobCode",
            &session.credentials.project_id,
            &session.credentials.api_key,
        );
        let resp = session
            .client()
            .post(&url)
            .bearer_auth(session.oauth_access_token().to_owned())
            .json(&UserRequest {
                idToken: None,
                uid: None,
                email: Some(user_email.to_string()),
                phoneNumber: None,
                requestType: Some("PASSWORD_RESET".to_string()),
            })
            .send()?;

        extract_google_api_error(resp, || user_email.to_owned())?;
        Ok({})
    }

    pub fn confirm_reset_password(
        session: &service_account::Session,
        oob_code: &str,
        new_password: &str,
    ) -> Result<()> {
        let url = firebase_auth_url("resetPassword", &session.credentials.api_key);

        #[allow(non_snake_case)]
        #[derive(Serialize)]
        struct Req {
            oobCode: String,
            newPassword: String,
        }

        let resp = session
            .client()
            .post(&url)
            .json(&Req {
                oobCode: oob_code.to_string(),
                newPassword: new_password.to_string(),
            })
            .send()?;

        extract_google_api_error(resp, || "resetPassword".to_owned())?;
        Ok({})
    }

    pub fn send_email_verification(
        session: &service_account::Session,
        user_id_token: &str,
    ) -> Result<()> {
        let url = firebase_auth_project_url(
            "sendOobCode",
            &session.credentials.project_id,
            &session.credentials.api_key,
        );

        let resp = session
            .client()
            .post(&url)
            .bearer_auth(session.oauth_access_token().to_owned())
            .json(&UserRequest {
                idToken: Some(user_id_token.to_owned()),
                uid: None,
                email: None,
                phoneNumber: None,
                requestType: Some("VERIFY_EMAIL".to_string()),
            })
            .send()?;

        extract_google_api_error(resp, || "sendOobCode:VERIFY_EMAIL".to_owned())?;
        Ok({})
    }

    pub fn confirm_email_verification(
        session: &service_account::Session,
        user_id: &str,
        oob_code: &str,
    ) -> Result<()> {
        let url = firebase_auth_project_url(
            "update",
            &session.credentials.project_id,
            &session.credentials.api_key,
        );

        #[allow(non_snake_case)]
        #[derive(Serialize)]
        struct Req {
            oobCode: String,
            localId: String,
        }

        let resp = session
            .client()
            .post(&url)
            .bearer_auth(session.oauth_access_token().to_owned())
            .json(&Req {
                localId: user_id.to_string(),
                oobCode: oob_code.to_string(),
            })
            .send()?;

        extract_google_api_error(resp, || "confirm_email_verification".to_owned())?;
        Ok({})
    }

    /// Generates the out-of-band email action link for email link sign-in flows, using the action
    ///  code settings provided.
    ///
    /// Error codes:
    /// - USER_NOT_FOUND
    pub fn email_sign_in_link(
        session: &service_account::Session,
        user_email: &str,
        opts: ActionCodeSettings,
    ) -> Result<String> {
        let url = firebase_auth_project_url(
            "sendOobCode",
            &session.credentials.project_id,
            &session.credentials.api_key,
        );
        #[allow(non_snake_case)]
        #[derive(Serialize)]
        struct Req {
            requestType: String,
            email: String,
            returnOobLink: bool,
            #[serde(flatten)]
            opts: ActionCodeSettings,
        }
        let resp = session
            .client()
            .post(&url)
            .bearer_auth(session.oauth_access_token().to_owned())
            .json(&Req {
                email: user_email.to_string(),
                requestType: "EMAIL_SIGNIN".to_string(),
                returnOobLink: true,
                opts,
            })
            .send()?;
        let resp = extract_google_api_error(resp, || user_email.to_owned())?;

        #[allow(non_snake_case)]
        #[derive(Deserialize, Serialize)]
        struct Res {
            oobLink: String,
        }

        let result: Res = resp.json()?;
        Ok(result.oobLink)
    }
}
