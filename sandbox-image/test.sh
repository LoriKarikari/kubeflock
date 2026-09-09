#!/usr/bin/env bash
set -euo pipefail

image=${1:-kubeflock-sandbox:test}
work=$(mktemp -d)
container=
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

if docker run --rm "$image" >"$work/startup.log" 2>&1; then
  echo "image started without SANDBOX_SSH_PUBKEY" >&2
  exit 1
fi
grep -qx 'SANDBOX_SSH_PUBKEY is required' "$work/startup.log"

ssh-keygen -q -t ed25519 -N '' -f "$work/key"
container=$(docker run -d \
  --add-host host.docker.internal:host-gateway \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /home/agent:uid=1000,gid=1000,mode=0700 \
  -e SSH_PORT=2200 \
  -e SANDBOX_SSH_PUBKEY="$(<"$work/key.pub")" \
  -p 127.0.0.1::2200 \
  "$image")

for _ in {1..30}; do
  if docker exec "$container" test -s /home/agent/sshd.pid; then break; fi
  sleep 1
done
docker exec "$container" test -s /home/agent/sshd.pid
docker exec "$container" sh -eu -c '
  test "$(id -u):$(id -g)" = 1000:1000
  test "$HERDR_PROCESS_DETECTION" = child-groups
  test "$(herdr --version)" = "herdr 0.9.0"
  test "$(pi --version)" = "0.85.1"
  command -v fd >/dev/null
  herdr integration status | grep -q "^pi: current"
  test -s "$HOME/.pi/agent/extensions/herdr-agent-state.ts"
  auth=$(pi auth check --provider openai --json --no-refresh || true)
  test "$auth" = '"'"'{"status":"not_ready","provider":"openai","reason":"credentials_not_configured"}'"'"'
'

port=$(docker port "$container" 2200/tcp)
port=${port##*:}
docker exec "$container" cat /home/agent/.ssh/ssh_host_ed25519_key.pub \
  | awk -v port="$port" '{print "[127.0.0.1]:" port " " $1 " " $2}' > "$work/known_hosts"
ssh_args=(
  -F /dev/null
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$work/known_hosts"
  -i "$work/key"
  -p "$port"
)
test "$(ssh "${ssh_args[@]}" agent@127.0.0.1 'id -u')" = 1000
echo "PASS: Sandbox image startup, authentication, and SSH"
