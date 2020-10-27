use firestore_db_and_auth::*;
use std::collections::HashMap;

const TEST_USER_ID: &str = include_str!("test_user_id.txt");

#[test]
fn user_info() -> errors::Result<()> {
    let cred = credentials::Credentials::from_file("firebase-service-account.json").expect("Read credentials file");

    let user_session = UserSession::by_user_id(&cred, TEST_USER_ID, false)?;

    println!("users::user_info");
    let user_info_container = users::user_info(&user_session)?;
    assert_eq!(user_info_container.users[0].localId.as_ref().unwrap(), TEST_USER_ID);

    Ok(())
}


#[test]
fn user_claims() -> errors::Result<()> {
    let cred = credentials::Credentials::from_file(
        "firebase-service-account.json").expect("Read credentials file");

    const BOB_ID: &str = "22Q2Ow9nJ0UM9cYOtkKH10NP3rj1";
    let session = ServiceSession::new(cred.clone())?;
    println!("SERVICE_ACCESS: {}", session.access_token());
    println!("SERVICE_ACCESS_0AUTH: {}", session.oauth_access_token());

    let user_session = UserSession::by_user_id(&cred, BOB_ID, false)?;
    let info = users::user_info(&user_session)?;
    println!("old customAttributes: {:?}", info.users.first().unwrap().customAttributes);


    let claims: HashMap<&str, &str> = {
        let mut claims = HashMap::new();
        claims.insert("premiumAccount", "TRUE");
        claims.insert("vehicle", "wagon");
        claims.insert("location", "twin peaks");
        claims
    };

    users::user_set_claims(&session, BOB_ID, claims.clone())?;

    let info = users::user_info(&user_session)?;
    let attributes = info.users.first().unwrap().customAttributes.clone();
    println!("new customAttributes: {:?}", attributes);
    assert_eq!(attributes, Some(serde_json::to_string(&claims).unwrap()));

    Ok(())
}
