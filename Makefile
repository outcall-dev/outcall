.PHONY: install-smoke install-smoke-doctor-codex install-smoke-doctor-claude

install-smoke:
	sh scripts/local-install-smoke.sh $(POST_INSTALL)

install-smoke-doctor-codex:
	sh scripts/local-install-smoke.sh outcall doctor codex

install-smoke-doctor-claude:
	sh scripts/local-install-smoke.sh outcall doctor claude
