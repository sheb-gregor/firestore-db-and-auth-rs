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
use crate::sessions::user::SessionAuth;
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
pub struct SignInUpUserResponse {
    pub localId: Option<String>,
    pub idToken: Option<String>,
    pub refreshToken: Option<String>,
    pub email: Option<String>,
    pub mfaPendingCredential: Option<String>,
    pub mfaInfo: Option<Vec<MfaInfo>>,
}

#[allow(non_snake_case)]
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct MfaInfo {
    pub phoneInfo: String,
    pub mfaEnrollmentId: String,
    pub displayName: String,
    pub enrolledAt: String,
}

#[allow(non_snake_case)]
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct MfaResponse {
    pub localId: Option<String>,
    pub mfaPendingCredential: String,
    pub mfaInfo: Vec<MfaInfo>,
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
) -> Result<user::SessionAuth> {
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
    session_auth_from_response(&session.credentials, resp)
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
) -> Result<user::SessionAuth> {
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
) -> Result<user::SessionAuth> {
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
    _user_id: &str,
    token: &str,
) -> Result<user::SessionAuth> {
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

    session_auth_from_response(&session.credentials, resp)
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

/// Generates the out-of-band email action link for email link sign-in flows, using the action
///  code settings provided.
///
/// # Arguments
/// * `session` - A session provider
/// * `user_email` - An email of the user to login.
/// * `return_oob_link` - Whether set true return link as string, otherwise send email.
/// * `opts` - Request options. `continueUrl` is required, other fields are optional.

/// Error codes:
/// - USER_NOT_FOUND
pub fn email_sign_in_link(
    session: &service_account::Session,
    user_email: &str,
    return_oob_link: bool,
    opts: ActionCodeSettings,
) -> Result<String> {
    let url = firebase_auth_url("sendOobCode", &session.credentials.api_key);
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
            returnOobLink: return_oob_link,
            opts,
        })
        .send()?;
    let resp = extract_google_api_error(resp, || user_email.to_owned())?;

    #[derive(Default, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", default)]
    struct Res {
        oob_link: String,
    }

    let result: Res = resp.json()?;
    Ok(result.oob_link)
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
) -> Result<user::SessionAuth> {
    let url = format!(
        "https://www.googleapis.com/identitytoolkit/v3/relyingparty/emailLinkSignin?key={}",
        &session.credentials.api_key
    );
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

    session_auth_from_response(&session.credentials, resp)
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct CaptchaParams {
    pub kind: String,
    pub recaptchaStoken: String,
    pub recaptchaSiteKey: String,
}

/// Gets parameters needed for generating a reCAPTCHA challenge.
pub fn request_captcha(session: &service_account::Session) -> Result<CaptchaParams> {
    let url = format!(
        "{}/v1/recaptchaParams?key={}",
        auth_host(),
        &session.credentials.api_key
    );

    let resp = session.client().get(&url).send()?;

    let resp = extract_google_api_error(resp, || "recaptchaParams".to_owned())?;
    let resp: CaptchaParams = resp.json()?;

    Ok(resp)
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyPhoneResp {
    pub sessionInfo: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct PhoneEnrollmentInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phoneNumber: Option<String>,
    pub recaptchaToken: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idToken: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct PhoneEnrollmentFinalize {
    pub code: String,
    pub sessionInfo: String,
}

/// Sends a SMS verification code for phone number sign-in.
pub fn verify_phone_number(
    session: &service_account::Session,
    phone: &str,
    captcha_token: &str,
    user_id_token: Option<String>,
) -> Result<VerifyPhoneResp> {
    let url = format!(
        "{}/v1/accounts:sendVerificationCode?key={}",
        auth_host(),
        &session.credentials.api_key
    );

    let resp = session
        .client()
        .post(&url)
        .json(&PhoneEnrollmentInfo {
            phoneNumber: Some(phone.to_owned()),
            recaptchaToken: captcha_token.to_owned(),
            idToken: user_id_token,
        })
        .send()?;

    let resp = extract_google_api_error(resp, || "accounts:sendVerificationCode".to_owned())?;

    let resp: VerifyPhoneResp = resp.json()?;
    Ok(resp)
}

/// Signs in a user with email and password. If the sign-in succeeds,
/// a new Identity Platform ID token and refresh token are issued for the authenticated user.
pub fn sign_in_with_phone(
    session: &service_account::Session,
    code: &str,
    session_info: &str,
) -> Result<user::SessionAuth> {
    let url = format!(
        "{}/v1/accounts:signInWithPhoneNumber?key={}",
        auth_host(),
        &session.credentials.api_key
    );

    let resp = session
        .client()
        .post(&url)
        .json(&PhoneEnrollmentFinalize {
            code: code.to_owned(),
            sessionInfo: session_info.to_owned(),
        })
        .send()?;

    let resp = extract_google_api_error(resp, || "accounts:signInWithPhoneNumber".to_owned())?;

    let resp: SignInUpUserResponse = resp.json()?;
    session_auth_from_response(&session.credentials, resp)
}

fn session_auth_from_response(
    credentials: &Credentials,
    resp: SignInUpUserResponse,
) -> Result<user::SessionAuth> {
    if resp.idToken.is_some() {
        let session =
            user::Session::by_access_token(credentials, &resp.idToken.unwrap_or_default())?;
        return Ok(user::SessionAuth::Completed(session));
    }

    return Ok(SessionAuth::MFARequired(MfaResponse {
        localId: resp.localId,
        mfaPendingCredential: resp.mfaPendingCredential.unwrap_or_default(),
        mfaInfo: resp.mfaInfo.unwrap_or_default(),
    }));
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct StartMfaSignInRequest {
    pub mfaEnrollmentId: String,
    pub mfaPendingCredential: String,
    pub phoneEnrollmentInfo: PhoneEnrollmentInfo,
    pub tenantId: Option<String>,
}

/// Sends the MFA challenge
///
/// Detailed info here:
/// https://cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaSignIn/start
pub fn sign_in_mfa_start(
    session: &service_account::Session,
    options: StartMfaSignInRequest,
) -> Result<VerifyPhoneResp> {
    let url = format!(
        "{}/v1/mfaSignIn:start?key={}",
        auth_host(),
        &session.credentials.api_key
    );

    let resp = session.client().post(&url).json(&options).send()?;
    let resp = extract_google_api_error(resp, || "confirm_email_verification".to_owned())?;

    #[allow(non_snake_case)]
    #[derive(Deserialize)]
    struct Response {
        phoneSessionInfo: VerifyPhoneResp,
    }

    let resp: Response = resp.json()?;
    Ok(resp.phoneSessionInfo)
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct FinalizeMfaSignInRequest {
    pub mfaPendingCredential: String,
    pub tenantId: Option<String>,
    pub phoneVerificationInfo: PhoneEnrollmentFinalize,
}

/// Verifies the MFA challenge and performs sign-in
///
/// Detailed info here:
/// https://cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaSignIn/finalize
///
pub fn sign_in_mfa_finalize(
    session: &service_account::Session,
    options: FinalizeMfaSignInRequest,
) -> Result<SignInUpUserResponse> {
    let url = format!(
        "{}/v2/accounts/mfaSignIn:finalize?key={}",
        auth_host(),
        &session.credentials.api_key
    );

    let resp = session.client().post(&url).json(&options).send()?;
    let resp = extract_google_api_error(resp, || "mfa_enrollment_finalize".to_owned())?;
    let resp: SignInUpUserResponse = resp.json()?;

    Ok(resp)
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
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct StartMfaEnrollmentRequest {
    pub idToken: String,
    pub tenantId: Option<String>,
    pub phoneEnrollmentInfo: PhoneEnrollmentInfo,
}

/// Step one of the MFA enrollment process.
/// In SMS case, this sends an SMS verification code to the user.
///
/// Detailed info here:
/// https://cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaEnrollment/start
pub fn mfa_enrollment_start(
    session: &service_account::Session,
    options: StartMfaEnrollmentRequest,
) -> Result<VerifyPhoneResp> {
    let url = format!(
        "{}/v1/mfaEnrollment:start?key={}",
        auth_host(),
        &session.credentials.api_key
    );

    let resp = session.client().post(&url).json(&options).send()?;
    let resp = extract_google_api_error(resp, || "confirm_email_verification".to_owned())?;

    #[allow(non_snake_case)]
    #[derive(Deserialize)]
    struct Response {
        phoneSessionInfo: VerifyPhoneResp,
    }

    let resp: Response = resp.json()?;
    Ok(resp.phoneSessionInfo)
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct FinalizeMfaEnrollmentRequest {
    pub idToken: String,
    pub displayName: String,
    pub tenantId: Option<String>,
    pub phoneVerificationInfo: PhoneEnrollmentFinalize,
}

/// Finishes enrolling a second factor for the user.
///
/// Detailed info here:
/// https://cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaEnrollment/finalize
///
pub fn mfa_enrollment_finalize(
    session: &service_account::Session,
    options: FinalizeMfaEnrollmentRequest,
) -> Result<SignInUpUserResponse> {
    let url = format!(
        "{}/v2/accounts/mfaEnrollment:finalize?key={}",
        auth_host(),
        &session.credentials.api_key
    );

    let resp = session.client().post(&url).json(&options).send()?;
    let resp = extract_google_api_error(resp, || "mfa_enrollment_finalize".to_owned())?;
    let resp: SignInUpUserResponse = resp.json()?;

    Ok(resp)
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WithdrawMfaEnrollmentRequest {
    pub idToken: String,
    pub mfaEnrollmentId: String,
    pub tenantId: Option<String>,
}

/// Revokes one second factor from the enrolled second factors for an account.
///
/// Detailed info here:
/// https://cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaEnrollment/withdraw
///
pub fn mfa_enrollment_withdraw(
    session: &service_account::Session,
    options: WithdrawMfaEnrollmentRequest,
) -> Result<SignInUpUserResponse> {
    let url = format!(
        "{}/v2/accounts/mfaEnrollment:withdraw?key={}",
        auth_host(),
        &session.credentials.api_key
    );

    let resp = session.client().post(&url).json(&options).send()?;
    let resp = extract_google_api_error(resp, || "mfa_enrollment_withdraw".to_owned())?;
    let resp: SignInUpUserResponse = resp.json()?;

    Ok(resp)
}
