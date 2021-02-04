use firestore_db_and_auth::jwt::JwtCustomClaims;
use firestore_db_and_auth::sessions::user::SessionAuth;
use firestore_db_and_auth::users::sign_in_with_custom_jwt;
use firestore_db_and_auth::*;
use std::collections::HashMap;

const TEST_USER_ID: &str = include_str!("test_user_id.txt");

fn service_account() -> String {
    std::env::set_var(
        "GOOGLE_APPLICATION_CREDENTIALS",
        "/home/sheb/Documents/gkeys/teamo-work.json",
    );
    std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .unwrap_or("firebase-service-account.json".to_string())
}

#[test]
fn user_info() {
    let cred =
        credentials::Credentials::from_file(&service_account()).expect("Read credentials file");

    let user_session = UserSession::by_user_id(&cred, TEST_USER_ID, false).unwrap();

    println!("users::user_info");
    let user_info_container = users::user_info(&user_session).unwrap();
    assert_eq!(
        user_info_container.users[0].localId.as_ref().unwrap(),
        TEST_USER_ID
    );
}

#[test]
fn should_sign_in_with_custom_token() {
    let cred =
        credentials::Credentials::from_file(&service_account()).expect("Read credentials file");
    let session = ServiceSession::new(cred.clone()).unwrap();

    const ALICE: &str = "alice@mail.com";
    let alice_user = users::get_user_by_email(&session, ALICE).unwrap();
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

    let token = jwt::create_custom_jwt_encoded(&cred, claims).unwrap();
    let user_session = sign_in_with_custom_jwt(&session, &alice_id, &token).unwrap();
    println!("{:?}", user_session.user_id);
}

#[test]
fn user_sign_up_and_sign_in() {
    let cred =
        credentials::Credentials::from_file(&service_account()).expect("Read credentials file");
    let session = ServiceSession::new(cred.clone()).unwrap();

    const ALICE: &str = "alice1@mail.com";
    const PASSWORD: &str = "alice_mail_com";

    users::sign_up(&session, ALICE, PASSWORD).unwrap();

    if let SessionAuth::Completed(user_session) = users::sign_in(&session, ALICE, PASSWORD).unwrap()
    {
        users::user_remove(&user_session).unwrap();
    }
}

#[test]
fn user_claims() -> errors::Result<()> {
    let cred =
        credentials::Credentials::from_file(&service_account()).expect("Read credentials file");

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

#[test]
fn get_email_with_sign_in_link() {
    let cred =
        credentials::Credentials::from_file(&service_account()).expect("Read credentials file");
    let session = ServiceSession::new(cred.clone()).unwrap();

    const ALICE: &str = "alice@sheb.me";

    let link = users::email_sign_in_link(
        &session,
        ALICE,
        true,
        users::ActionCodeSettings {
            continueUrl: "http://localhost:5000/#".to_string(),
            canHandleCodeInApp: true,
            iOSBundleId: None,
            androidPackageName: None,
            androidMinimumVersion: None,
            androidInstallApp: None,
            dynamicLinkDomain: None,
        },
    )
    .unwrap();
    println!("{}", link);

    // users::sign_in_with_email_link(
    //     &session,
    //     ALICE,
    //     "a8QQxl8kdP2Oguosgw4eu0c-ClQA1d9k7arwDtmx08AAAAF29DqIuQ",
    // )
    // .unwrap();
}
