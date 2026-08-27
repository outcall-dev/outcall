pub(crate) fn invoking_container_user() -> Option<String> {
    invoking_unix_user()
}

#[cfg(unix)]
fn invoking_unix_user() -> Option<String> {
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    (uid != 0 && gid != 0).then(|| format!("{uid}:{gid}"))
}

#[cfg(not(unix))]
fn invoking_unix_user() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoking_user_is_non_root_when_available() {
        if let Some(user) = invoking_container_user() {
            assert!(outcall_api::valid_container_user(&user));
        }
    }
}
