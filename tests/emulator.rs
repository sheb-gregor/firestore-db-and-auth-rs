use firestore_db_and_auth::errors::{extract_google_api_error, FirebaseError};
use firestore_db_and_auth::sessions::service_account;
use firestore_db_and_auth::sessions::user::SessionAuth;
use firestore_db_and_auth::{credentials, errors, users, FirebaseAuthBearer, ServiceSession};
use std::collections::HashMap;

fn get_emulator_session() -> errors::Result<ServiceSession> {
    std::env::set_var(
        "GOOGLE_APPLICATION_CREDENTIALS",
        "/home/sheb/Documents/gkeys/teamo-work.json",
    );
    // std::env::set_var("FIREBASE_AUTH_EMULATOR_HOST", "localhost:9090");
    // std::env::set_var("FIRESTORE_EMULATOR_HOST", "localhost:8080");
    let credentials_path = "/home/sheb/Documents/gkeys/teamo-work.json";
    let credentials = credentials::Credentials::from_file(credentials_path)?;
    credentials.verify()?;
    ServiceSession::new(credentials.clone())
}

#[test]
fn sign_up() {
    let session = get_emulator_session().unwrap();
    let user = "test_user@gmail.com";
    let user_pass = "test_pass";
    println!("try to sign_in");
    let user_session = users::sign_up(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    if let SessionAuth::Completed(user_session) = user_session {
        users::user_remove(&user_session).unwrap();
    }
}

#[test]
fn sign_in() {
    let session = get_emulator_session().unwrap();
    let user = "test_user@gmail.com";
    let user_pass = "test_pass";
    println!("try to sign_in");
    let user_session = users::sign_up(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    let new_user_session = users::sign_in(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);
    assert_eq!(user_session.user_id, new_user_session.user_id);

    if let SessionAuth::Completed(user_session) = new_user_session {
        users::user_remove(&user_session).unwrap();
    }
}

#[test]
fn change_password() {
    let session = get_emulator_session().unwrap();
    let user = "test_user@gmail.com";
    let user_pass = "test_pass";
    println!("try to sign_in");
    let user_session = users::sign_up(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    let new_user_pass = "new_test_pass";

    users::ManageUser::change_password(&session, &user_session.user_id, new_user_pass).unwrap();

    let new_user_session = users::sign_in(&session, user, new_user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);
    assert_eq!(user_session.user_id, new_user_session.user_id);

    if let SessionAuth::Completed(user_session) = new_user_session {
        users::user_remove(&user_session).unwrap();
    }
}

#[test]
fn reset_password() {
    let session = get_emulator_session().unwrap();
    let user = "test_user@gmail.com";
    let user_pass = "test_pass";
    println!("try to sign_in");
    let user_session = users::sign_up(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    users::ManageUser::send_reset_password_email(&session, user).unwrap();
    let _codes = get_verification_codes(&session).unwrap();

    let new_user_pass = "new_test_pass";
    users::ManageUser::confirm_reset_password(&session, "", new_user_pass).unwrap();

    let new_user_session = users::sign_in(&session, user, new_user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);
    assert_eq!(user_session.user_id, new_user_session.user_id);

    if let SessionAuth::Completed(user_session) = new_user_session {
        users::user_remove(&user_session).unwrap();
    }
}

#[test]
fn reset_password_p1() {
    let session = get_emulator_session().unwrap();
    let user = "mefapa7700@ofdow.com";
    let user_pass = "test_pass_123123adewq";
    println!("try to sign_in");
    let user_session = users::sign_up(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    users::ManageUser::send_reset_password_email(&session, user).unwrap();
}

#[test]
fn reset_password_p2() {
    let session = get_emulator_session().unwrap();
    let user = "mefapa7700@ofdow.com";
    let user_pass = "test_pass_123123adewq";
    println!("try to sign_in");
    let user_session = users::sign_in(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    // users::ManageUser::send_reset_password_email(&session, user).unwrap();
    let code = "EypNsIUYO-Xp1NHFn_H5xojDVO4U89kVZrPrjtTVt_gAAAF2G34-Jg";
    //
    let new_user_pass = "new_test_pass";
    users::ManageUser::confirm_reset_password(&session, code, new_user_pass).unwrap();
    //
    let new_user_session = users::sign_in(&session, user, new_user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);
    assert_eq!(user_session.user_id, new_user_session.user_id);
    //
    if let SessionAuth::Completed(user_session) = new_user_session {
        users::user_remove(&user_session).unwrap();
    }
}

#[test]
fn change_email() {
    let session = get_emulator_session().unwrap();
    let user = "mefapa7700@mail.com";
    let user_pass = "test_pass_123123adewq";
    println!("try to sign_in");
    let user_session = users::sign_up(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    let new_email = "test_qe@mail.com";
    users::ManageUser::change_email(&session, &user_session.user_id, new_email).unwrap();
    let new_user_session = users::sign_in(&session, new_email, user_pass).unwrap();
    assert_eq!(user_session.user_id, new_user_session.user_id);
    if let SessionAuth::Completed(user_session) = new_user_session {
        users::user_remove(&user_session).unwrap();
    }
}

#[test]
fn verify_email_p1() {
    let session = get_emulator_session().unwrap();
    let user = "mefapa7700@ofdow.com";
    let user_pass = "test_pass_123123adewq";
    println!("try to sign_in");
    let user_session = users::sign_in(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    users::ManageUser::send_email_verification(&session, &user_session.access_token()).unwrap();
}

#[test]
fn verify_email_p2() {
    let session = get_emulator_session().unwrap();
    let user = "mefapa7700@ofdow.com";
    let user_pass = "test_pass_123123adewq";
    println!("try to sign_in");
    let user_session = users::sign_in(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);

    let code = "TJJAOcfVjEoEUHvq-XCLPrypF2eybg3Roz-8bmfXDpkAAAF2G4bbJQ";
    //
    users::ManageUser::confirm_email_verification(&session, &user_session.user_id, code).unwrap();
    //
    let new_user_session = users::sign_in(&session, user, user_pass).unwrap();
    println!("user_id: {}", user_session.user_id);
    assert_eq!(user_session.user_id, new_user_session.user_id);

    // users::user_remove(&new_user_session).unwrap();
}

fn get_verification_codes(
    session: &service_account::Session,
) -> errors::Result<HashMap<String, serde_json::Value>> {
    let url = match std::env::var("FIREBASE_AUTH_EMULATOR_HOST") {
        Ok(v) => format!(
            "http://{}/emulator/v1/projects/{}/verificationCodes",
            v, session.credentials.project_id
        ),
        Err(_) => return Err(FirebaseError::Generic("emulator host not set")),
    };
    let resp = session.client().get(&url).send()?;

    let resp = extract_google_api_error(resp, || "verificationCodes".to_owned())?;

    let resp: HashMap<String, serde_json::Value> = resp.json()?;
    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
    Ok(resp)
}
