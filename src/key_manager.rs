use super::common::AUTH_KEY_LENGTH;
use crate::utils::current_time;
use derive_more::{Display, Error};
use log::debug;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Serialize;

#[derive(Serialize, Debug, Eq, PartialEq, Clone)]
pub struct AuthKey {
    pub key: String,
    pub valid_until: Option<u64>,
}

impl AuthKey {
    pub fn generate(seconds_valid: u64) -> Self {
        let key: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(AUTH_KEY_LENGTH)
            .map(char::from)
            .collect();

        debug!(
            "Generated key: {}, valid for: {} seconds",
            key, seconds_valid
        );

        Self {
            key,
            valid_until: Some(current_time() + seconds_valid),
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        let current_time = current_time();

        match self.valid_until {
            Some(valid_until) if valid_until < current_time => Ok(()),
            Some(_) => Err(Error::KeyExpired),
            None => Err(Error::KeyInvalid),
        }
    }

    pub fn from_buffer(key_buffer: [u8; AUTH_KEY_LENGTH]) -> Option<Self> {
        String::from_utf8(Vec::from(key_buffer))
            .ok()
            .map(|key| Self {
                key,
                valid_until: None,
            })
    }

    pub fn from_string(key: &str) -> Option<Self> {
        (key.len() == AUTH_KEY_LENGTH).then(|| Self {
            key: key.to_string(),
            valid_until: None,
        })
    }
}

#[derive(Debug, Display, PartialEq, Error)]
#[allow(dead_code)]
pub enum Error {
    #[display(fmt = "Key could not be verified.")]
    KeyVerificationError,
    #[display(fmt = "Key is invalid.")]
    KeyInvalid,
    #[display(fmt = "Key has expired.")]
    KeyExpired,
}

impl From<r2d2_sqlite::rusqlite::Error> for Error {
    fn from(e: r2d2_sqlite::rusqlite::Error) -> Self {
        debug!("{}", e);
        Error::KeyVerificationError
    }
}

#[cfg(test)]
mod tests {
    use crate::key_manager::AuthKey;

    #[test]
    fn auth_key_from_buffer() {
        let auth_key = AuthKey::from_buffer([
            89, 90, 83, 108, 52, 108, 77, 90, 117, 112, 82, 117, 79, 112, 83, 82, 67, 51, 107, 114,
            73, 75, 82, 53, 66, 80, 66, 49, 52, 110, 114, 74,
        ]);

        assert!(auth_key.is_some());
        assert_eq!(auth_key.unwrap().key, "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ");
    }

    #[test]
    fn auth_key_from_string() {
        let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
        let auth_key = AuthKey::from_string(key_string);

        assert!(auth_key.is_some());
        assert_eq!(auth_key.unwrap().key, key_string);
    }

    #[test]
    fn generate_valid_auth_key() {
        let auth_key = AuthKey::generate(9999);

        assert!(&auth_key.verify().is_ok());
    }

    #[test]
    fn generate_expired_auth_key() {
        let mut auth_key = AuthKey::generate(0);
        auth_key.valid_until = Some(0);

        assert!(&auth_key.verify().is_err());
    }
}
