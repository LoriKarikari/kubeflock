ARG NODE_IMAGE=node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
FROM ${NODE_IMAGE}

ARG HERDR_VERSION=0.9.0
ARG PI_VERSION=0.85.1
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl fd-find git jq openssh-client openssh-server python3 ripgrep socat \
 && rm -rf /var/lib/apt/lists/* \
 && case "$TARGETARCH" in \
      amd64) asset=x86_64; checksum=4fa1a01158dd8043da92d31b270780b0dcc10603038d9b61cac4d81ab63fb71f ;; \
      arm64) asset=aarch64; checksum=9c8db20fb7e7427b138d5367113f1621ffd319f2f65d6f009e2594029115f0d2 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL --retry 3 \
      "https://github.com/herdrdev/herdr/releases/download/v${HERDR_VERSION}/herdr-linux-${asset}" \
      -o /tmp/herdr \
 && echo "$checksum  /tmp/herdr" | sha256sum -c - \
 && install -m 0755 /tmp/herdr /usr/local/bin/herdr \
 && rm /tmp/herdr \
 && npm install --global "@earendil-works/pi-coding-agent@${PI_VERSION}" \
 && rm -rf /root/.npm /etc/ssh/ssh_host_* \
 && ln -s /usr/bin/fdfind /usr/local/bin/fd \
 && groupmod --new-name agent node \
 && usermod --login agent --home /home/agent --move-home --shell /bin/bash node \
 && install -d -o agent -g agent -m 0700 /home/agent/.ssh \
 && install -d -o agent -g agent -m 0755 /run/sshd

COPY --chmod=0755 entrypoint.sh /usr/local/bin/kubeflock-entrypoint

ENV HOME=/home/agent
USER 1000:1000
WORKDIR /home/agent
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/kubeflock-entrypoint"]
