use firestore_db_and_auth::jwt::JwtCustomClaims;
use firestore_db_and_auth::users::sign_in_with_custom_jwt;
use firestore_db_and_auth::*;
use std::collections::HashMap;

const TEST_USER_ID: &str = include_str!("test_user_id.txt");

#[test]
fn user_info() -> errors::Result<()> {
    let cred = credentials::Credentials::from_file("firebase-service-account.json")
        .expect("Read credentials file");

    let user_session = UserSession::by_user_id(&cred, TEST_USER_ID, false)?;

    println!("users::user_info");
    let user_info_container = users::user_info(&user_session)?;
    assert_eq!(
        user_info_container.users[0].localId.as_ref().unwrap(),
        TEST_USER_ID
    );

    Ok(())
}

#[test]
fn should_sign_in_with_custom_token() -> errors::Result<()> {
    let cred = credentials::Credentials::from_file("firebase-service-account.json")
        .expect("Read credentials file");
    let session = ServiceSession::new(cred.clone())?;

    const ALICE: &str = "alice@mail.com";
    let alice_user = users::get_user_by_email(&session, ALICE)?;
    print!("{:?}", alice_user);
    let alice_id = alice_user.localId.unwrap();

    let claims: HashMap<&str, &str> = {
        let mut claims = HashMap::new();
        claims.insert("premiumAccount", "false");
        claims.insert("vehicle", "wagon");
        claims.insert("location", "twin peaks");
        claims
    };

    let claims = JwtCustomClaims::new(&alice_id.clone(), claims);

    let token = jwt::create_custom_jwt_encoded(&cred, claims)?;
    let user_session = sign_in_with_custom_jwt(&session, &alice_id, &token)?;
    println!("{:?}", user_session.user_id);
    Ok(())
}

#[test]
fn user_claims() -> errors::Result<()> {
    let cred = credentials::Credentials::from_file("firebase-service-account.json")
        .expect("Read credentials file");

    const ALICE: &str = "alice@mail.com";
    let session = ServiceSession::new(cred.clone())?;
    println!("SERVICE_ACCESS: {}", session.access_token());
    println!("SERVICE_ACCESS_0AUTH: {}", session.oauth_access_token());

    let alice_user = users::get_user_by_email(&session, ALICE)?;
    print!("{:?}", alice_user);
    let alice_id = alice_user.localId.unwrap();
    let user_session = UserSession::by_user_id(&cred, &alice_id, false)?;
    let info = users::user_info(&user_session)?;
    println!(
        "old customAttributes: {:?}",
        info.users.first().unwrap().customAttributes
    );

    let claims: HashMap<&str, &str> = {
        let mut claims = HashMap::new();
        claims.insert("premiumAccount", "TRUE");
        claims.insert("vehicle", "wagon");
        claims.insert("location", "twin peaks");
        claims
    };

    users::user_set_claims(&session, &alice_id, claims.clone())?;

    let info = users::user_info(&user_session)?;
    let attributes = info.users.first().unwrap().customAttributes.clone();
    println!("new customAttributes: {:?}", attributes);
    assert_eq!(attributes, Some(serde_json::to_string(&claims).unwrap()));

    Ok(())
}
