use std::collections::HashMap;

use crate::docker::ManagedContainerIdentity;

const MAX_SESSIONS: usize = 4_096;

struct Session {
    container: ManagedContainerIdentity,
}

#[derive(Default)]
pub(super) struct SessionRegistry {
    by_token: HashMap<String, Session>,
    by_container: HashMap<String, String>,
}

impl SessionRegistry {
    pub(super) fn existing_for_container(
        &mut self,
        container_id: &str,
    ) -> Option<(String, ManagedContainerIdentity)> {
        let token = self.by_container.get(container_id)?.clone();
        match self.by_token.get(&token) {
            Some(session) => Some((token, session.container.clone())),
            None => {
                self.by_container.remove(container_id);
                None
            }
        }
    }

    pub(super) fn insert(
        &mut self,
        token: String,
        container: ManagedContainerIdentity,
    ) -> anyhow::Result<()> {
        let replacing = self.by_container.contains_key(&container.id);
        if !replacing && self.by_token.len() >= MAX_SESSIONS {
            anyhow::bail!("agent session limit reached");
        }
        if let Some(old_token) = self
            .by_container
            .insert(container.id.clone(), token.clone())
        {
            self.by_token.remove(&old_token);
        }
        self.by_token.insert(token, Session { container });
        Ok(())
    }

    pub(super) fn container_for_token(&self, token: &str) -> Option<&ManagedContainerIdentity> {
        self.by_token.get(token).map(|session| &session.container)
    }

    pub(super) fn remove_container(&mut self, container_id: &str) {
        if let Some(token) = self.by_container.remove(container_id) {
            self.by_token.remove(&token);
        }
    }

    pub(super) fn clear(&mut self) {
        self.by_token.clear();
        self.by_container.clear();
    }
}

pub(super) fn generate_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)?;
    Ok(format!("tok-{}", hex_encode(&bytes)))
}

pub(super) fn valid_session_token(token: &str) -> bool {
    has_canonical_hex_suffix(token, "tok-", 32)
}

fn has_canonical_hex_suffix(value: &str, prefix: &str, hex_len: usize) -> bool {
    value.len() == prefix.len() + hex_len
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(id: &str) -> ManagedContainerIdentity {
        ManagedContainerIdentity {
            id: id.to_string(),
            name: "project-1".to_string(),
        }
    }

    #[test]
    fn replaces_only_the_same_container_session() {
        let first = container("container-a");
        let second = container("container-b");
        let mut sessions = SessionRegistry::default();
        sessions.insert("tok-a".to_string(), first.clone()).unwrap();
        sessions
            .insert("tok-b".to_string(), second.clone())
            .unwrap();

        assert_eq!(sessions.container_for_token("tok-a"), Some(&first));
        assert_eq!(sessions.container_for_token("tok-b"), Some(&second));

        sessions
            .insert("tok-a2".to_string(), first.clone())
            .unwrap();
        assert!(sessions.container_for_token("tok-a").is_none());
        assert_eq!(sessions.container_for_token("tok-a2"), Some(&first));
        assert_eq!(sessions.container_for_token("tok-b"), Some(&second));
    }

    #[test]
    fn removes_container_session() {
        let mut sessions = SessionRegistry::default();
        sessions
            .insert("tok-a".to_string(), container("container-a"))
            .unwrap();

        sessions.remove_container("container-a");

        assert!(sessions.container_for_token("tok-a").is_none());
        assert!(sessions.existing_for_container("container-a").is_none());
    }

    #[test]
    fn clears_all_sessions_after_identity_reset() {
        let mut sessions = SessionRegistry::default();
        sessions
            .insert("tok-a".to_string(), container("container-a"))
            .unwrap();
        sessions
            .insert("tok-b".to_string(), container("container-b"))
            .unwrap();

        sessions.clear();

        assert!(sessions.container_for_token("tok-a").is_none());
        assert!(sessions.existing_for_container("container-b").is_none());
    }

    #[test]
    fn generated_tokens_have_canonical_format() {
        let token = generate_token().unwrap();
        assert!(valid_session_token(&token));
        assert!(!valid_session_token("tok-ABCDEFABCDEFABCDEFABCDEFABCDEFAB"));
        assert!(!valid_session_token("tok-short"));
        assert!(!valid_session_token(
            "other-0123456789abcdef0123456789abcdef"
        ));
    }
}
