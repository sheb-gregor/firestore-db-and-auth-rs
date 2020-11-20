use firestore_db_and_auth::{credentials, errors, users, ServiceSession};

fn get_emulator_session() -> errors::Result<ServiceSession> {
    std::env::set_var(
        "GOOGLE_APPLICATION_CREDENTIALS",
        "tests/test-service-account.json",
    );
    std::env::set_var("FIREBASE_AUTH_EMULATOR_HOST", "localhost:9090");
    std::env::set_var("FIRESTORE_EMULATOR_HOST", "localhost:8080");
    let credentials_path = "tests/test-service-account.json";
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

    users::user_remove(&user_session).unwrap();
}

#[test]
fn sign_in() -> errors::Result<()> {
    let session = get_emulator_session()?;
    let user = "test_user@gmail.com";
    let user_pass = "test_pass";
    println!("try to sign_in");
    let user_session = users::sign_up(&session, user, user_pass)?;
    println!("user_id: {}", user_session.user_id);

    let new_user_session = users::sign_in(&session, user, user_pass)?;
    println!("user_id: {}", user_session.user_id);
    assert_eq!(user_session.user_id, new_user_session.user_id);

    users::user_remove(&new_user_session)?;
    Ok(())
}
