//! # A Firestore Auth Session token is a Javascript Web Token (JWT). This module contains JWT helper functions.

use crate::credentials::Credentials;
use crate::errors::FirebaseError;
use biscuit::jwa::SignatureAlgorithm;
use biscuit::{ClaimPresenceOptions, SingleOrMultiple, StringOrUri, ValidationOptions};
use chrono::{Duration, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ops::Add;
use std::ops::Deref;
use std::slice::Iter;
use std::str::FromStr;

type Error = super::errors::FirebaseError;

pub static JWT_AUDIENCE_FIRESTORE: &str =
    "https://firestore.googleapis.com/google.firestore.v1.Firestore";
pub static JWT_AUDIENCE_IDENTITY: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

pub trait PrivateClaims
where
    Self: Serialize + DeserializeOwned + Clone + Default,
{
    fn get_scopes(&self) -> HashSet<String>;
    fn get_client_id(&self) -> Option<String>;
    fn get_uid(&self) -> Option<String>;
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct JwtOAuthPrivateClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>, // Probably the firebase User ID if set
}

impl JwtOAuthPrivateClaims {
    pub fn new<S: AsRef<str>>(
        scope: Option<Iter<S>>,
        client_id: Option<String>,
        user_id: Option<String>,
    ) -> Self {
        JwtOAuthPrivateClaims {
            scope: scope.and_then(|f| {
                Some(f.fold(String::new(), |acc, x| {
                    let x: &str = x.as_ref();
                    return acc + x + " ";
                }))
            }),
            client_id,
            uid: user_id,
        }
    }
}

impl PrivateClaims for JwtOAuthPrivateClaims {
    fn get_scopes(&self) -> HashSet<String> {
        match self.scope {
            Some(ref v) => v.split(" ").map(|f| f.to_owned()).collect(),
            None => HashSet::new(),
        }
    }

    fn get_client_id(&self) -> Option<String> {
        self.client_id.clone()
    }

    fn get_uid(&self) -> Option<String> {
        self.uid.clone()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct JwtCustomClaims {
    pub uid: String,
    pub claims: HashMap<String, Value>,
}

impl JwtCustomClaims {
    pub fn new<T: Serialize>(uid: &str, claims: T) -> Self {
        let dev_claims = {
            let val = serde_json::to_string(&claims).unwrap_or("".to_string());
            serde_json::from_str::<HashMap<String, Value>>(&val).unwrap_or_default()
        };
        JwtCustomClaims {
            claims: dev_claims,
            uid: uid.to_string(),
        }
    }
}

impl PrivateClaims for JwtCustomClaims {
    fn get_scopes(&self) -> HashSet<String> {
        HashSet::new()
    }

    fn get_client_id(&self) -> Option<String> {
        None
    }

    fn get_uid(&self) -> Option<String> {
        Some(self.uid.clone())
    }
}

pub(crate) type AuthClaimsJWT = biscuit::JWT<JwtOAuthPrivateClaims, biscuit::Empty>;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct JWSEntry {
    #[serde(flatten)]
    pub(crate) headers: biscuit::jws::RegisteredHeader,
    #[serde(flatten)]
    pub(crate) ne: biscuit::jwk::RSAKeyParameters,
}

#[derive(Serialize, Deserialize)]
pub struct JWKSetDTO {
    pub keys: Vec<JWSEntry>,
}

/// Download the Google JWK Set for a given service account.
/// The resulting set of JWKs need to be added to a credentials object
/// for jwk verifications.
pub fn download_google_jwks(account_mail: &str) -> Result<JWKSetDTO, Error> {
    let resp = reqwest::blocking::Client::new()
        .get(&format!(
            "https://www.googleapis.com/service_accounts/v1/jwk/{}",
            account_mail
        ))
        .send()?;
    let jwk_set: JWKSetDTO = resp.json()?;
    Ok(jwk_set)
}

/// Download the Google JWK Set for a given service account.
/// The resulting set of JWKs need to be added to a credentials object
/// for jwk verifications.
pub async fn download_google_jwks_async(account_mail: &str) -> Result<JWKSetDTO, Error> {
    let resp = reqwest::Client::new()
        .get(&format!(
            "https://www.googleapis.com/service_accounts/v1/jwk/{}",
            account_mail
        ))
        .send()
        .await?;
    let jwk_set: JWKSetDTO = resp.json().await?;
    Ok(jwk_set)
}

/// Returns true if the access token (assumed to be a jwt) has expired
///
/// An error is returned if the given access token string is not a jwt
pub(crate) fn is_expired(
    access_token: &str,
    tolerance_in_minutes: i64,
) -> Result<bool, FirebaseError> {
    let token = AuthClaimsJWT::new_encoded(&access_token);
    let claims = token.unverified_payload()?;
    if let Some(expiry) = claims.registered.expiry.as_ref() {
        let diff: Duration = Utc::now().signed_duration_since(expiry.deref().clone());
        return Ok(diff.num_minutes() - tolerance_in_minutes > 0);
    }

    Ok(true)
}

/// Returns true if the jwt was updated and needs signing
pub(crate) fn jwt_update_expiry_if(jwt: &mut AuthClaimsJWT, expire_in_minutes: i64) -> bool {
    let ref mut claims = jwt.payload_mut().unwrap().registered;

    let now = biscuit::Timestamp::from(Utc::now());
    if let Some(issued_at) = claims.issued_at.as_ref() {
        let diff: Duration = Utc::now().signed_duration_since(issued_at.deref().clone());
        if diff.num_minutes() > expire_in_minutes {
            claims.issued_at = Some(now);
        } else {
            return false;
        }
    } else {
        claims.issued_at = Some(now);
    }

    true
}

pub(crate) fn create_jwt<S>(
    credentials: &Credentials,
    scope: Option<Iter<S>>,
    duration: chrono::Duration,
    client_id: Option<String>,
    user_id: Option<String>,
    audience: &str,
) -> Result<AuthClaimsJWT, Error>
where
    S: AsRef<str>,
{
    let claims = JwtOAuthPrivateClaims::new(scope, client_id, user_id);

    create_jwt_with_claims(credentials, duration, audience, claims)
}

pub(crate) fn create_jwt_encoded<S: AsRef<str>>(
    credentials: &Credentials,
    scope: Option<Iter<S>>,
    duration: chrono::Duration,
    client_id: Option<String>,
    user_id: Option<String>,
    audience: &str,
) -> Result<String, Error> {
    let jwt = create_jwt(credentials, scope, duration, client_id, user_id, audience)?;
    let secret = credentials
        .keys
        .secret
        .as_ref()
        .ok_or(Error::Generic("No private key added via add_keypair_key!"))?;
    Ok(jwt.encode(&secret.deref())?.encoded()?.encode())
}

fn create_jwt_with_claims<T>(
    credentials: &Credentials,
    duration: chrono::Duration,
    audience: &str,
    claims: T,
) -> Result<biscuit::JWT<T, biscuit::Empty>, Error>
where
    T: Serialize + DeserializeOwned,
{
    use biscuit::{
        jws::{Header, RegisteredHeader},
        ClaimsSet, Empty, RegisteredClaims,
    };

    let header: Header<Empty> = Header::from(RegisteredHeader {
        algorithm: SignatureAlgorithm::RS256,
        key_id: Some(credentials.private_key_id.to_owned()),
        ..Default::default()
    });

    let expected_claims = ClaimsSet::<T> {
        registered: RegisteredClaims {
            issuer: Some(FromStr::from_str(&credentials.client_email)?),
            audience: Some(SingleOrMultiple::Single(StringOrUri::from_str(audience)?)),
            expiry: Some(biscuit::Timestamp::from(Utc::now().add(duration))),
            subject: Some(StringOrUri::from_str(&credentials.client_email)?),
            issued_at: Some(biscuit::Timestamp::from(Utc::now())),
            ..Default::default()
        },
        private: claims,
    };
    Ok(biscuit::JWT::new_decoded(header, expected_claims))
}

pub fn create_custom_jwt_encoded<T: PrivateClaims>(
    credentials: &Credentials,
    claims: T,
) -> Result<String, Error> {
    let jwt = create_jwt_with_claims(
        &credentials,
        Duration::hours(1),
        JWT_AUDIENCE_IDENTITY,
        claims,
    )?;
    let secret = credentials
        .keys
        .secret
        .as_ref()
        .ok_or(FirebaseError::Generic(
            "No private key added via add_keypair_key!",
        ))?;
    Ok(jwt.encode(&secret.deref())?.encoded()?.encode())
}

pub struct TokenValidationResult<T: PrivateClaims = JwtOAuthPrivateClaims> {
    pub claims: T,
    pub audience: String,
    pub subject: String,
}

impl TokenValidationResult {
    pub fn get_scopes(&self) -> HashSet<String> {
        self.claims.get_scopes()
    }
}

pub(crate) fn verify_access_token(
    credentials: &Credentials,
    access_token: &str,
) -> Result<TokenValidationResult, Error> {
    verify_access_token_with_claims(credentials, access_token)
}

pub fn verify_access_token_with_claims<T: PrivateClaims>(
    credentials: &Credentials,
    access_token: &str,
) -> Result<TokenValidationResult<T>, Error> {
    let token = biscuit::JWT::<T, biscuit::Empty>::new_encoded(&access_token);

    let header = token.unverified_header()?;
    let kid = header
        .registered
        .key_id
        .as_ref()
        .ok_or(FirebaseError::Generic("No jwt kid"))?;
    let secret = credentials
        .decode_secret(kid)
        .ok_or(FirebaseError::Generic("No secret for kid"))?;

    let token = token.into_decoded(&secret.deref(), SignatureAlgorithm::RS256)?;

    use biscuit::Presence::*;

    let o = ValidationOptions {
        claim_presence_options: ClaimPresenceOptions {
            issued_at: Required,
            not_before: Optional,
            expiry: Required,
            issuer: Required,
            audience: Required,
            subject: Required,
            id: Optional,
        },
        // audience: Validation::Validate(StringOrUri::from_str(JWT_SUBJECT)?),
        ..Default::default()
    };

    let claims = token.payload()?;
    claims.registered.validate(o)?;

    let audience = match claims.registered.audience.as_ref().unwrap() {
        SingleOrMultiple::Single(v) => v.to_string(),
        SingleOrMultiple::Multiple(v) => v.get(0).unwrap().to_string(),
    };

    Ok(TokenValidationResult {
        claims: claims.private.clone(),
        subject: claims.registered.subject.as_ref().unwrap().to_string(),
        audience,
    })
}
