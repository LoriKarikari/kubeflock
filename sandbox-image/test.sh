#!/usr/bin/env bash
set -euo pipefail

image=${1:-kubeflock-sandbox:test}
work=$(mktemp -d)
container=
provider=
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  if [[ -n "$provider" ]]; then kill "$provider" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

if docker run --rm "$image" >"$work/startup.log" 2>&1; then
  echo "image started without SANDBOX_SSH_PUBKEY" >&2
  exit 1
fi
grep -qx 'SANDBOX_SSH_PUBKEY is required' "$work/startup.log"

ssh-keygen -q -t ed25519 -N '' -f "$work/key"
node "$(dirname "$0")/test-provider.mjs" > "$work/provider-port" &
provider=$!
for _ in {1..30}; do
  if [[ -s "$work/provider-port" ]]; then break; fi
  sleep 0.1
done
provider_port=$(<"$work/provider-port")
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
docker exec -i "$container" sh -c 'cat > "$HOME/.pi/agent/models.json"' <<EOF
{"providers":{"fixture":{"baseUrl":"http://host.docker.internal:$provider_port/v1","api":"openai-completions","apiKey":"fixture","models":[{"id":"fixture"}]}}}
EOF
ssh "${ssh_args[@]}" agent@127.0.0.1 \
  'herdr --session agent workspace create --cwd /home/agent --label smoke --no-focus' \
  | grep -q '"type":"workspace_created"'
ssh "${ssh_args[@]}" agent@127.0.0.1 \
  'herdr --session agent agent start smoke --kind pi --pane w1:p1 --timeout 30000 -- --provider fixture --model fixture' \
  | grep -q '"agent_status":"idle"'
ssh "${ssh_args[@]}" agent@127.0.0.1 \
  'herdr --session agent agent explain w1:p1' \
  | grep -q 'screen_detection_skip_reason: full_lifecycle_hook_authority'
ssh "${ssh_args[@]}" agent@127.0.0.1 \
  'herdr --session agent agent prompt w1:p1 "reply once" --wait' > "$work/prompt" &
prompt=$!
ssh "${ssh_args[@]}" agent@127.0.0.1 \
  'herdr --session agent agent wait w1:p1 --until working --timeout 5000' \
  | grep -q '"agent_status":"working"'
wait "$prompt"
grep -q '"agent_status":"idle"' "$work/prompt"
ssh "${ssh_args[@]}" agent@127.0.0.1 \
  'herdr --session agent agent wait w1:p1 --until idle --timeout 5000' \
  | grep -q '"agent_status":"idle"'
echo "PASS: Sandbox image startup, authentication, SSH, and Pi lifecycle"
