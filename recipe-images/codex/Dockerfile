FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-client bash curl \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g @openai/codex \
  && codex --version

# Outcall's hardened Docker container is the security boundary. Codex's Linux
# bwrap sandbox needs capabilities that managed agent containers intentionally
# do not receive, so avoid a fragile nested sandbox while retaining approvals.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'exec codex --sandbox danger-full-access "$@"' \
    > /usr/local/bin/outcall-codex \
  && chmod 0755 /usr/local/bin/outcall-codex

WORKDIR /workspace
ENTRYPOINT ["outcall-codex"]
