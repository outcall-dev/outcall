.PHONY: build coverage spec-check ui-test stop install-smoke install-smoke-doctor-codex install-smoke-doctor-claude release-security-gate

COVERAGE_MIN_LINES ?= 50

build:
	@cargo build --workspace --locked || { \
		tmp_target="$$(mktemp -d "$${TMPDIR:-/tmp}/outcall-build-target.XXXXXX")"; \
		echo "default Cargo target dir unavailable; retrying with CARGO_TARGET_DIR=$$tmp_target"; \
		CARGO_TARGET_DIR="$$tmp_target" cargo build --workspace --locked; \
	}

coverage:
	mkdir -p target/coverage
	cargo llvm-cov --workspace --all-targets --locked --lcov --output-path target/coverage/lcov.info
	cargo llvm-cov report --summary-only --fail-under-lines $(COVERAGE_MIN_LINES)

spec-check:
	scripts/check-spec-traceability.sh

ui-test:
	node --check outcall-ui/assets/app.js
	node --test outcall-ui/tests/*.test.js

stop:
	@true

install-smoke:
	sh scripts/local-install-smoke.sh $(POST_INSTALL)

install-smoke-doctor-codex:
	sh scripts/local-install-smoke.sh outcall doctor codex

install-smoke-doctor-claude:
	sh scripts/local-install-smoke.sh outcall doctor claude

release-security-gate:
	scripts/verify-release-security-gate.sh
