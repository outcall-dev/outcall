.PHONY: build stop install-smoke install-smoke-doctor-codex install-smoke-doctor-claude

build:
	@cargo build --workspace --locked || { \
		tmp_target="$$(mktemp -d "$${TMPDIR:-/tmp}/outcall-build-target.XXXXXX")"; \
		echo "default Cargo target dir unavailable; retrying with CARGO_TARGET_DIR=$$tmp_target"; \
		CARGO_TARGET_DIR="$$tmp_target" cargo build --workspace --locked; \
	}

stop:
	@true

install-smoke:
	sh scripts/local-install-smoke.sh $(POST_INSTALL)

install-smoke-doctor-codex:
	sh scripts/local-install-smoke.sh outcall doctor codex

install-smoke-doctor-claude:
	sh scripts/local-install-smoke.sh outcall doctor claude
