# Kubeflock Sandbox image

The starter image runs a rootless SSH server and a headless Herdr server. It includes:

- Herdr 0.9.0
- Pi 0.85.1 with the Herdr integration
- Node.js 24.15.0
- Git, OpenSSH, `socat`, `curl`, `fd`, `jq`, `ripgrep`, Python 3, and build tools

The image supports `linux/amd64` and `linux/arm64`. It enables Herdr's `child-groups` process-detection fallback because gVisor does not expose terminal foreground process groups.

## Build and test

```bash
docker build --tag kubeflock-sandbox:test sandbox-image
sandbox-image/test.sh kubeflock-sandbox:test
```

The test runs the image as UID/GID 1000 with all capabilities dropped and no privilege escalation. It checks SSH on a non-default port, missing provider credentials, and failed startup.

## Configure

Set these environment variables through the Sandbox template:

- `SANDBOX_SSH_PUBKEY` contains the allowed public SSH key and is required.
- `SSH_PORT` selects the SSH port and defaults to 2222.

Mount persistent storage at `/home/agent`. The entrypoint stores SSH host keys, the authorized key, the Herdr state, the Pi integration, Pi sessions, and provider credentials in that home.

Authenticate from a terminal inside the Sandbox. For example, run `pi`, enter `/login`, and complete the provider flow. If OAuth redirects to an unreachable `localhost` callback, copy the failed redirect URL from the browser and paste it into Pi's login prompt. Treat that URL as a credential and do not share it.

Pi can store the resulting credential in `/home/agent/.pi/agent/auth.json`. The credential persists with the home volume. It is not part of the image layer, build output, Kubeflock state, or plugin logs.
