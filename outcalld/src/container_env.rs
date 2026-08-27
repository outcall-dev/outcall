pub(crate) fn container_environment(
    proxy_addr: Option<&str>,
    extra: Option<Vec<String>>,
) -> Vec<String> {
    const RESERVED_KEYS: [&str; 6] = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ];

    let mut env = proxy_addr.map_or_else(Vec::new, |proxy_addr| {
        let proxy_url = format!("http://{proxy_addr}");
        vec![
            format!("HTTP_PROXY={proxy_url}"),
            format!("HTTPS_PROXY={proxy_url}"),
            "NO_PROXY=localhost,127.0.0.1".to_string(),
            format!("http_proxy={proxy_url}"),
            format!("https_proxy={proxy_url}"),
            "no_proxy=localhost,127.0.0.1".to_string(),
        ]
    });
    env.extend(extra.unwrap_or_default().into_iter().filter(|entry| {
        let key = entry
            .split_once('=')
            .map(|(key, _)| key)
            .unwrap_or(entry.as_str());
        !RESERVED_KEYS.contains(&key)
    }));
    env
}

#[cfg(test)]
mod tests {
    use super::container_environment;

    #[test]
    fn enforces_unique_proxy_values() {
        let env = container_environment(
            Some("10.200.0.1:8080"),
            Some(vec![
                "HOME=/home/node".to_string(),
                "HTTP_PROXY=http://untrusted:1234".to_string(),
                "HTTPS_PROXY=http://untrusted:1234".to_string(),
                "NO_PROXY=*".to_string(),
                "http_proxy=http://untrusted:1234".to_string(),
                "https_proxy=http://untrusted:1234".to_string(),
                "no_proxy=*".to_string(),
                "CODEX_API_KEY=test".to_string(),
            ]),
        );

        assert_eq!(
            env,
            vec![
                "HTTP_PROXY=http://10.200.0.1:8080",
                "HTTPS_PROXY=http://10.200.0.1:8080",
                "NO_PROXY=localhost,127.0.0.1",
                "http_proxy=http://10.200.0.1:8080",
                "https_proxy=http://10.200.0.1:8080",
                "no_proxy=localhost,127.0.0.1",
                "HOME=/home/node",
                "CODEX_API_KEY=test",
            ]
        );
    }

    #[test]
    fn disabled_proxy_omits_reserved_proxy_variables() {
        let env = container_environment(
            None,
            Some(vec![
                "HOME=/home/node".to_string(),
                "HTTP_PROXY=http://untrusted:1234".to_string(),
                "no_proxy=*".to_string(),
            ]),
        );

        assert_eq!(env, vec!["HOME=/home/node"]);
    }
}
