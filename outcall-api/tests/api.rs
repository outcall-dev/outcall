//! Unit tests for outcall-api — S012-FR-005.
//!
//! Covers: type round-trips, ApiResponse helpers, constant values,
//! default construction, and edge cases in serde serialization.

mod serde_roundtrips {
    use outcall_api::*;

    #[test]
    fn action_type_snake_case_serialization() {
        for (variant, expected) in [
            (ActionType::ToolExec, "\"tool_exec\""),
            (ActionType::NetworkCall, "\"network_call\""),
            (ActionType::FileAccess, "\"file_access\""),
            (ActionType::ShellExec, "\"shell_exec\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn action_type_deserialization() {
        for (json_str, variant) in [
            ("\"tool_exec\"", ActionType::ToolExec),
            ("\"network_call\"", ActionType::NetworkCall),
            ("\"file_access\"", ActionType::FileAccess),
            ("\"shell_exec\"", ActionType::ShellExec),
        ] {
            let parsed: ActionType = serde_json::from_str(json_str).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn rule_action_roundtrip() {
        for action in [RuleAction::Allow, RuleAction::Block, RuleAction::Enrich] {
            let json = serde_json::to_string(&action).unwrap();
            let back: RuleAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    #[test]
    fn decision_roundtrip() {
        for decision in [Decision::Allow, Decision::Block] {
            let json = serde_json::to_string(&decision).unwrap();
            let back: Decision = serde_json::from_str(&json).unwrap();
            assert_eq!(back, decision);
        }
    }

    #[test]
    fn rule_request_status_roundtrip() {
        for status in [
            RuleRequestStatus::Pending,
            RuleRequestStatus::Approved,
            RuleRequestStatus::Rejected,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: RuleRequestStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn checkin_data_roundtrip() {
        let data = CheckinData {
            container_id: "outcall-agent-a3f7b201".into(),
            session_token: "tok_19f0a3c1".into(),
            context_keys: vec!["dns".into(), "http".into()],
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: CheckinData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.container_id, data.container_id);
        assert_eq!(back.session_token, data.session_token);
        assert_eq!(back.context_keys, data.context_keys);
    }

    #[test]
    fn verdict_roundtrip() {
        let verdict = Verdict {
            allowed: true,
            matched_rule: Some("allow-all".into()),
            reason: Some("first match wins".into()),
        };
        let json = serde_json::to_string(&verdict).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.allowed, verdict.allowed);
        assert_eq!(back.matched_rule, verdict.matched_rule);
        assert_eq!(back.reason, verdict.reason);
    }

    #[test]
    fn permission_request_roundtrip() {
        let mut meta = std::collections::HashMap::new();
        meta.insert("remote_addr".into(), "10.0.0.2".into());
        let req = PermissionRequest {
            action_type: ActionType::NetworkCall,
            target: "tcp:443".into(),
            metadata: Some(meta),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PermissionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "tcp:443");
        assert!(back.metadata.is_some());
    }

    #[test]
    fn eval_context_with_dns_roundtrip() {
        let ctx = EvalContext {
            dns: Some(DnsContext {
                query: "evil.example.com".into(),
                record_type: "A".into(),
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: EvalContext = serde_json::from_str(&json).unwrap();
        assert!(back.dns.is_some());
        assert_eq!(back.dns.as_ref().unwrap().query, "evil.example.com");
    }

    #[test]
    fn eval_context_with_network_roundtrip() {
        let ctx = EvalContext {
            network: Some(NetworkContext {
                hostname: Some("proxy.local".into()),
                ip: "10.0.1.50".into(),
                port: 8080,
                protocol: "tcp".into(),
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: EvalContext = serde_json::from_str(&json).unwrap();
        let net = back.network.unwrap();
        assert_eq!(net.ip, "10.0.1.50");
        assert_eq!(net.port, 8080);
    }

    #[test]
    fn eval_context_with_http_roundtrip() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let ctx = EvalContext {
            http: Some(HttpContext {
                method: "POST".into(),
                path: "/v1/messages".into(),
                host: "api.anthropic.com".into(),
                headers,
                body_size: 128,
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: EvalContext = serde_json::from_str(&json).unwrap();
        let http = back.http.unwrap();
        assert_eq!(http.method, "POST");
        assert_eq!(http.path, "/v1/messages");
    }

    #[test]
    fn eval_context_with_docker_roundtrip() {
        let ctx = EvalContext {
            docker: Some(DockerContext {
                image: "outcall-dev/agent:latest".into(),
                command: vec!["outcall-agent".into(), "run".into()],
                volumes: vec!["/var/run/outcall.sock:/run/outcall/agent.sock".into()],
                env_keys: vec!["OUTCALL_MODE".into(), "RUST_LOG".into()],
                capabilities: vec!["NET_ADMIN".into()],
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: EvalContext = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.docker.as_ref().unwrap().image,
            "outcall-dev/agent:latest"
        );
    }

    #[test]
    fn evaluate_result_roundtrip() {
        let result = EvaluateResult {
            decision: Decision::Block,
            matched_rule: Some("block-evil".into()),
            file: Some("test.yaml".into()),
            logged: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: EvaluateResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.decision, Decision::Block));
        assert_eq!(back.matched_rule.as_deref(), Some("block-evil"));
    }

    #[test]
    fn rule_summary_roundtrip() {
        let summary = RuleSummary {
            id: "allow-all".into(),
            file: "test.yaml".into(),
            action: RuleAction::Allow,
            condition_preview: "true".into(),
            description: Some("allow everything".into()),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: RuleSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "allow-all");
        assert!(matches!(back.action, RuleAction::Allow));
    }

    #[test]
    fn bridge_status_roundtrip() {
        let status = BridgeStatus {
            name: "outcall0".into(),
            up: true,
            index: Some(12),
            nftables_active: true,
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: BridgeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "outcall0");
        assert!(back.up);
        assert_eq!(back.index, Some(12));
    }

    #[test]
    fn dns_filter_status_roundtrip() {
        let status = DnsFilterStatus {
            running: true,
            listen_address: "0.0.0.0".into(),
            listen_port: 53,
            upstreams: vec!["8.8.8.8".into(), "1.1.1.1".into()],
            cache_entries: 42,
            queries_total: 1000,
            queries_allowed: 900,
            queries_blocked: 100,
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: DnsFilterStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.listen_port, 53);
        assert_eq!(back.queries_blocked, 100);
    }

    #[test]
    fn proxy_status_roundtrip() {
        let status = ProxyStatus {
            running: true,
            listen_address: "127.0.0.1".into(),
            proxy_url: "http://127.0.0.1:8080".into(),
            active_connections: 5,
            total_requests: 10000,
            total_blocked: 500,
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: ProxyStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_requests, 10000);
    }

    #[test]
    fn network_create_request_roundtrip() {
        let req = NetworkCreateRequest {
            name: Some("test-net".into()),
            subnet: Some("10.201.0.0/24".into()),
            gateway: Some("10.201.0.1".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: NetworkCreateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name.as_deref(), Some("test-net"));
    }

    #[test]
    fn network_container_roundtrip() {
        let container = NetworkContainer {
            name: "outcall-agent-a3f7b201".into(),
            ipv4_address: "10.200.0.5".into(),
        };
        let json = serde_json::to_string(&container).unwrap();
        let back: NetworkContainer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ipv4_address, "10.200.0.5");
    }

    #[test]
    fn container_create_request_roundtrip() {
        let req = ContainerCreateRequest {
            image: "outcall-dev/agent:latest".into(),
            network: Some("outcall-default".into()),
            name: Some("my-agent".into()),
            user: Some("1000:1000".into()),
            memory_limit: Some(256 * 1024 * 1024),
            cpu_shares: None,
            env: Some(vec!["FOO=bar".into()]),
            cmd: Some(vec!["--version".into()]),
            entrypoint: Some(vec!["codex".into()]),
            working_dir: Some("/workspace".into()),
            volumes: Some(vec!["/tmp/project:/workspace".into()]),
            include_outcall_helper_mounts: Some(false),
            interactive: Some(true),
            tty: Some(true),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ContainerCreateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.image, "outcall-dev/agent:latest");
        assert_eq!(back.memory_limit, Some(256 * 1024 * 1024));
        assert_eq!(back.user.as_deref(), Some("1000:1000"));
        assert_eq!(back.entrypoint, Some(vec!["codex".into()]));
        assert_eq!(back.working_dir.as_deref(), Some("/workspace"));
        assert_eq!(back.include_outcall_helper_mounts, Some(false));
        assert_eq!(back.interactive, Some(true));
        assert_eq!(back.tty, Some(true));
    }

    #[test]
    fn allow_rule_request_roundtrip() {
        let req = AllowRuleRequest {
            container: "outcall-agent-a3f7b201".into(),
            src_ip: "10.200.0.5".into(),
            destination: "github.com".into(),
            protocol: Some("tcp".into()),
            port: Some(443),
            expires_in_secs: Some(60),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: AllowRuleRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.destination, "github.com");
        assert_eq!(back.port, Some(443));
        assert_eq!(back.expires_in_secs, Some(60));
    }

    #[test]
    fn active_rule_roundtrip() {
        let rule = ActiveRule {
            container: "outcall-agent-a3f7b201".into(),
            src_ip: "10.200.0.5".into(),
            destination: "1.2.3.4/32".into(),
            protocol: Some("tcp".into()),
            port: Some(443),
            nft_handle: 12345,
            inserted_at: "2026-05-05T12:00:00Z".into(),
            expires_in_secs: Some(59),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: ActiveRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nft_handle, 12345);
        assert_eq!(back.expires_in_secs, Some(59));
    }

    #[test]
    fn flush_dynamic_result_roundtrip() {
        let result = FlushDynamicResult { removed: 7 };
        let json = serde_json::to_string(&result).unwrap();
        let back: FlushDynamicResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.removed, 7);
    }

    #[test]
    fn reload_result_roundtrip() {
        let result = ReloadResult {
            files_loaded: 3,
            rules_loaded: 17,
            warnings: vec!["duplicate rule id: allow-all".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ReloadResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules_loaded, 17);
    }

    #[test]
    fn approve_rule_result_uses_rule_count_and_accepts_legacy_field() {
        let result = ApproveRuleResult {
            id: "rr-aabbcc112233".into(),
            rules_loaded: 17,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["rules_loaded"], 17);
        assert!(json.get("nft_handle").is_none());

        let legacy: ApproveRuleResult = serde_json::from_value(serde_json::json!({
            "id": "rr-aabbcc112233",
            "nft_handle": 17
        }))
        .unwrap();
        assert_eq!(legacy.rules_loaded, 17);
    }

    #[test]
    fn test_expression_request_and_result_roundtrip() {
        let req = TestExpressionRequest {
            expression: "dns.query == \"evil.example.com\"".into(),
            context: EvalContext {
                dns: Some(DnsContext {
                    query: "evil.example.com".into(),
                    record_type: "A".into(),
                }),
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: TestExpressionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expression, "dns.query == \"evil.example.com\"");

        let result = TestExpressionResult {
            result: true,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TestExpressionResult = serde_json::from_str(&json).unwrap();
        assert!(back.result);
    }
}

mod api_response_helpers {
    use outcall_api::*;

    #[test]
    fn api_response_ok_sets_success_and_data() {
        let resp = ApiResponse::ok(42);
        assert!(resp.success);
        assert_eq!(resp.data, Some(42));
        assert!(resp.error.is_none());
    }

    #[test]
    fn api_response_err_sets_failure_and_error() {
        let resp: ApiResponse<i32> = ApiResponse::err("something went wrong");
        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert_eq!(resp.error.as_deref(), Some("something went wrong"));
    }

    #[test]
    fn api_response_ok_with_complex_type() {
        let verdict = Verdict {
            allowed: true,
            matched_rule: Some("allow-all".into()),
            reason: None,
        };
        let resp = ApiResponse::ok(verdict);
        assert!(resp.success);
        assert!(resp.data.as_ref().unwrap().allowed);
    }

    #[test]
    fn api_response_ok_unit_type() {
        let resp: ApiResponse<()> = ApiResponse::ok(());
        assert!(resp.success);
        assert!(resp.data.is_some());
    }

    #[test]
    fn api_response_err_with_static_str() {
        let resp: ApiResponse<String> = ApiResponse::err("static error");
        assert!(!resp.success);
        assert_eq!(resp.error.as_deref(), Some("static error"));
    }

    #[test]
    fn api_response_err_with_string() {
        let msg = String::from("dynamic error message");
        let resp: ApiResponse<String> = ApiResponse::err(msg);
        assert!(!resp.success);
    }
}

mod serde_skip_attrs {
    use outcall_api::*;

    #[test]
    fn permission_request_metadata_none_not_serialized() {
        let req = PermissionRequest {
            action_type: ActionType::NetworkCall,
            target: "tcp:443".into(),
            metadata: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("metadata"));
        let back: PermissionRequest = serde_json::from_str(&json).unwrap();
        assert!(back.metadata.is_none());
    }

    #[test]
    fn permission_request_metadata_some_serialized() {
        let mut meta = std::collections::HashMap::new();
        meta.insert("key".into(), "value".into());
        let req = PermissionRequest {
            action_type: ActionType::NetworkCall,
            target: "tcp:443".into(),
            metadata: Some(meta),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("metadata"));
    }

    #[test]
    fn evaluate_result_optional_fields_none() {
        let result = EvaluateResult {
            decision: Decision::Allow,
            matched_rule: None,
            file: None,
            logged: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("matched_rule"));
        assert!(json.contains("file"));
        let back: EvaluateResult = serde_json::from_str(&json).unwrap();
        assert!(back.matched_rule.is_none());
        assert!(back.file.is_none());
    }

    #[test]
    fn api_response_omits_none_fields() {
        let resp: ApiResponse<i32> = ApiResponse::err("error");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("data"));
        assert!(json.contains("error"));
    }
}

mod constants {
    use outcall_api::*;

    #[test]
    fn unreachable_exit_code_is_5() {
        assert_eq!(UNREACHABLE_EXIT_CODE, 5);
    }

    #[test]
    fn default_request_timeout_is_30_secs() {
        assert_eq!(DEFAULT_REQUEST_TIMEOUT_SECS, 30);
    }

    #[test]
    fn default_heartbeat_interval_is_10_secs() {
        assert_eq!(DEFAULT_HEARTBEAT_INTERVAL_SECS, 10);
    }

    #[test]
    fn default_sockets_have_expected_paths() {
        assert_eq!(DEFAULT_HOST_SOCKET, "/tmp/outcall/host.sock");
        assert_eq!(DEFAULT_AGENT_SOCKET, "/tmp/outcall/agent.sock");
    }

    #[test]
    fn default_bridge_name() {
        assert_eq!(DEFAULT_BRIDGE_NAME, "outcall0");
    }

    #[test]
    fn network_constants() {
        assert_eq!(NETWORK_PREFIX, "outcall-");
        assert_eq!(DEFAULT_NETWORK_NAME, "outcall-default");
        assert_eq!(SUBNET_BLOCK, "10.200.0.0/16");
        assert_eq!(DEFAULT_SUBNET, "10.200.0.0/24");
        assert_eq!(DEFAULT_GATEWAY, "10.200.0.1");
    }

    #[test]
    fn container_constants() {
        assert_eq!(CONTAINER_PREFIX, "outcall-");
        assert_eq!(AGENT_SOCKET_CONTAINER_PATH, "/run/outcall/agent.sock");
        assert_eq!(SHIM_CONTAINER_PATH, "/usr/local/bin/outcall");
        assert_eq!(DEFAULT_STOP_TIMEOUT_SECS, 10);
        assert_eq!(MAX_STOP_TIMEOUT_SECS, 300);
        assert_eq!(MAX_CONTAINER_NAME_BYTES, 128);
        assert_eq!(DEFAULT_MEMORY_LIMIT, 512 * 1024 * 1024);
        assert_eq!(MIN_MEMORY_LIMIT, 6 * 1024 * 1024);
        assert_eq!(DEFAULT_CPU_SHARES, 1024);
        assert_eq!(MIN_CPU_SHARES, 2);
        assert_eq!(DEFAULT_PID_LIMIT, 256);
        assert!(valid_memory_limit(MIN_MEMORY_LIMIT));
        assert!(!valid_memory_limit(MIN_MEMORY_LIMIT - 1));
        assert!(valid_cpu_shares(MIN_CPU_SHARES));
        assert!(valid_cpu_shares(MAX_CPU_SHARES));
        assert!(!valid_cpu_shares(MIN_CPU_SHARES - 1));
        assert!(!valid_cpu_shares(MAX_CPU_SHARES + 1));
        assert!(valid_container_name("project-1"));
        assert!(!valid_container_name("/project-1"));
        assert!(!valid_container_name(
            &"a".repeat(MAX_CONTAINER_NAME_BYTES + 1)
        ));
        assert!(valid_stop_timeout(0));
        assert!(valid_stop_timeout(MAX_STOP_TIMEOUT_SECS));
        assert!(!valid_stop_timeout(-1));
        assert!(!valid_stop_timeout(MAX_STOP_TIMEOUT_SECS + 1));
    }

    #[test]
    fn managed_container_users_are_numeric_and_non_root() {
        assert!(valid_container_user(DEFAULT_CONTAINER_USER));
        assert!(valid_container_user("501:20"));
        for invalid in [
            "",
            "root",
            "0:0",
            "0:20",
            "501:0",
            "501",
            "501:20:1",
            "+501:20",
            "501:+20",
            " 501:20",
            "501:20 ",
        ] {
            assert!(!valid_container_user(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn rule_identifiers_are_safe_and_bounded() {
        assert!(valid_rule_id("allow-api.example_1"));
        assert!(!valid_rule_id(""));
        assert!(!valid_rule_id("allow\r\nX-Injected: yes"));
        assert!(!valid_rule_id(&"a".repeat(MAX_RULE_ID_BYTES + 1)));
    }

    #[test]
    fn host_socket_deny_paths_contains_host_socket() {
        assert!(HOST_SOCKET_DENY_PATHS.contains(&DEFAULT_HOST_SOCKET));
    }
}

mod default_construction {
    use outcall_api::*;

    #[test]
    fn eval_context_defaults_to_all_none() {
        let ctx = EvalContext::default();
        assert!(ctx.network.is_none());
        assert!(ctx.http.is_none());
        assert!(ctx.dns.is_none());
        assert!(ctx.docker.is_none());
        assert!(ctx.run.is_none());
    }

    #[test]
    fn network_context_defaults() {
        let ctx = NetworkContext::default();
        assert_eq!(ctx.hostname, None);
        assert_eq!(ctx.ip, "");
        assert_eq!(ctx.port, 0);
        assert_eq!(ctx.protocol, "");
    }

    #[test]
    fn http_context_defaults() {
        let ctx = HttpContext::default();
        assert_eq!(ctx.method, "");
        assert_eq!(ctx.path, "");
        assert_eq!(ctx.host, "");
        assert!(ctx.headers.is_empty());
        assert_eq!(ctx.body_size, 0);
    }

    #[test]
    fn dns_context_defaults() {
        let ctx = DnsContext::default();
        assert_eq!(ctx.query, "");
        assert_eq!(ctx.record_type, "");
    }

    #[test]
    fn docker_context_defaults() {
        let ctx = DockerContext::default();
        assert_eq!(ctx.image, "");
        assert!(ctx.command.is_empty());
        assert!(ctx.volumes.is_empty());
        assert!(ctx.env_keys.is_empty());
        assert!(ctx.capabilities.is_empty());
    }

    #[test]
    fn run_context_defaults() {
        let ctx = RunContext::default();
        assert_eq!(ctx.tool, "");
        assert!(ctx.args.is_empty());
        assert!(ctx.flags.is_empty());
        assert_eq!(ctx.cwd, "");
        assert!(ctx.context.is_empty());
    }
}

mod edge_cases {
    use outcall_api::*;

    #[test]
    fn empty_dns_query_roundtrips() {
        let ctx = EvalContext {
            dns: Some(DnsContext {
                query: "".into(),
                record_type: "A".into(),
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: EvalContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dns.as_ref().unwrap().query, "");
    }

    #[test]
    fn decision_block_serialization() {
        let json = serde_json::to_string(&Decision::Block).unwrap();
        assert_eq!(json, "\"block\"");
    }

    #[test]
    fn decision_allow_serialization() {
        let json = serde_json::to_string(&Decision::Allow).unwrap();
        assert_eq!(json, "\"allow\"");
    }

    #[test]
    fn action_enrich_serialization() {
        let json = serde_json::to_string(&RuleAction::Enrich).unwrap();
        assert_eq!(json, "\"enrich\"");
    }

    #[test]
    fn network_status_with_no_optional_fields() {
        let status = NetworkStatus {
            exists: false,
            network_id: None,
            name: "nonexistent".into(),
            subnet: None,
            gateway: None,
            containers: vec![],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("network_id"));
        assert!(json.contains("subnet"));
    }

    #[test]
    fn container_info_full_roundtrip() {
        let info = ContainerInfo {
            container_id: "abc123def456".into(),
            name: "outcall-agent-a3f7b201".into(),
            image: "outcall-dev/agent:latest".into(),
            state: "running".into(),
            network: "outcall-default".into(),
            created_at: "2026-05-05T10:00:00Z".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: ContainerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, "running");
    }

    #[test]
    fn dns_cache_entry_roundtrip() {
        let entry = DnsCacheEntry {
            hostname: "google.com".into(),
            record_type: "AAAA".into(),
            ttl_remaining_secs: 300,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DnsCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hostname, "google.com");
    }

    #[test]
    fn allow_rule_request_optional_fields_none() {
        let req = AllowRuleRequest {
            container: "outcall-agent-a3f7b201".into(),
            src_ip: "10.200.0.5".into(),
            destination: "0.0.0.0/0".into(),
            protocol: None,
            port: None,
            expires_in_secs: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: AllowRuleRequest = serde_json::from_str(&json).unwrap();
        assert!(back.protocol.is_none());
        assert!(back.port.is_none());
        assert!(back.expires_in_secs.is_none());
        assert!(!json.contains("expires_in_secs"));

        let legacy: AllowRuleRequest = serde_json::from_str(
            r#"{"container":"legacy","src_ip":"10.0.0.2","destination":"1.1.1.1","protocol":null,"port":null}"#,
        )
        .unwrap();
        assert!(legacy.expires_in_secs.is_none());
    }

    #[test]
    fn agent_rule_submit_request_roundtrip() {
        let req = AgentRuleSubmitRequest {
            rule_file: r#"
version: "1"
rules:
  - id: allow-all
    condition: 'true'
    action: allow
"#
            .into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: AgentRuleSubmitRequest = serde_json::from_str(&json).unwrap();
        assert!(back.rule_file.contains("allow-all"));
    }
}
