FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-client bash curl gnupg \
  && install -d -m 0755 /etc/apt/keyrings \
  && curl -fsSL https://downloads.claude.ai/keys/claude-code.asc \
    -o /etc/apt/keyrings/claude-code.asc \
  && gpg --batch --show-keys --with-colons /etc/apt/keyrings/claude-code.asc \
    | grep -q ':31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE:' \
  && printf '%s\n' \
    'deb [signed-by=/etc/apt/keyrings/claude-code.asc] https://downloads.claude.ai/claude-code/apt/stable stable main' \
    > /etc/apt/sources.list.d/claude-code.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends claude-code \
  && rm -rf /var/lib/apt/lists/* /root/.gnupg \
  && claude --version

WORKDIR /workspace
ENTRYPOINT ["claude"]
