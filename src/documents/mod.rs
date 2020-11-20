//! # Firestore Document Access
//!
//! Interact with Firestore documents.
//! Please check the root page of this documentation for examples.

use super::dto;
use super::errors::{extract_google_api_error, FirebaseError, Result};
use super::firebase_rest_to_rust::{document_to_pod, pod_to_document};
use super::FirebaseAuthBearer;

use serde::{Deserialize, Serialize};
use std::path::Path;

mod delete;
mod list;
mod query;
mod read;
mod write;

pub use delete::*;
pub use list::*;
pub use query::*;
pub use read::*;
pub use write::*;

/// An [`Iterator`] implementation that provides a join method
///
/// [`Iterator`]: https://doc.rust-lang.org/std/iter/trait.Iterator.html
pub trait JoinableIterator: Iterator {
    fn join(&mut self, sep: &str) -> String
    where
        Self::Item: std::fmt::Display,
    {
        use std::fmt::Write;
        match self.next() {
            None => String::new(),
            Some(first_elt) => {
                // estimate lower bound of capacity needed
                let (lower, _) = self.size_hint();
                let mut result = String::with_capacity(sep.len() * lower);
                write!(&mut result, "{}", first_elt).unwrap();
                for elt in self {
                    result.push_str(sep);
                    write!(&mut result, "{}", elt).unwrap();
                }
                result
            }
        }
    }
}

impl<'a, VALUE> JoinableIterator for std::collections::hash_map::Keys<'a, String, VALUE> {}

#[inline]
fn firebase_url_query(v1: &str) -> String {
    format!(
        "{}/v1/projects/{}/databases/(default)/documents:runQuery",
        firebase_host(),
        v1
    )
}

#[inline]
fn firebase_url_base(v1: &str) -> String {
    format!("{}/v1/{}", firebase_host(), v1)
}

#[inline]
fn firebase_url_extended(project: &str, v2: &str, v3: &str) -> String {
    format!(
        "{}/v1/projects/{}/databases/(default)/documents/{}/{}",
        firebase_host(),
        project,
        v2,
        v3
    )
}

fn firebase_host() -> String {
    match std::env::var("FIRESTORE_EMULATOR_HOST") {
        Ok(v) => format!("http://{}", v),
        Err(_) => "https://firestore.googleapis.com".to_string(),
    }
}

#[inline]
fn firebase_url(project: &str, collection: &str) -> String {
    format!(
        "{}/v1/projects/{}/databases/(default)/documents/{}?",
        firebase_host(),
        project,
        collection
    )
}

/// Converts an absolute path like "projects/{PROJECT_ID}/databases/(default)/documents/my_collection/document_id"
/// into a relative document path like "my_collection/document_id"
///
/// This is usually used to get a suitable path for [`delete`].
pub fn abs_to_rel(path: &str) -> &str {
    &path[path.find("(default)").unwrap() + 20..]
}

#[test]
fn abs_to_rel_test() {
    assert_eq!(
        abs_to_rel("projects/{PROJECT_ID}/databases/(default)/documents/my_collection/document_id"),
        "my_collection/document_id"
    );
}
