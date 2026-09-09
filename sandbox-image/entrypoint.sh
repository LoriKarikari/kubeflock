#!/bin/sh
set -eu

SSH_PORT="${SSH_PORT:-2222}"
case "$SSH_PORT" in
  ""|*[!0-9]*) echo "SSH_PORT must be an integer from 1 to 65535" >&2; exit 1 ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "SSH_PORT must be an integer from 1 to 65535" >&2
  exit 1
fi
if [ "$(id -u)" -ne 1000 ] || [ "$(id -g)" -ne 1000 ]; then
  echo "Kubeflock Sandbox images must run as UID/GID 1000" >&2
  exit 1
fi
if [ -z "${SANDBOX_SSH_PUBKEY:-}" ]; then
  echo "SANDBOX_SSH_PUBKEY is required" >&2
  exit 1
fi

umask 077
mkdir -p "$HOME/.ssh" "$HOME/.pi/agent"
printf '%s\n' "$SANDBOX_SSH_PUBKEY" > "$HOME/.ssh/authorized_keys.new"
if ! ssh-keygen -l -f "$HOME/.ssh/authorized_keys.new" >/dev/null 2>&1; then
  rm -f "$HOME/.ssh/authorized_keys.new"
  echo "SANDBOX_SSH_PUBKEY is invalid" >&2
  exit 1
fi
mv "$HOME/.ssh/authorized_keys.new" "$HOME/.ssh/authorized_keys"

if [ ! -f "$HOME/.ssh/ssh_host_ed25519_key" ]; then
  ssh-keygen -q -t ed25519 -N '' -f "$HOME/.ssh/ssh_host_ed25519_key"
fi

herdr integration install pi >/dev/null
/usr/sbin/sshd -e \
  -o "Port=$SSH_PORT" \
  -o "PidFile=$HOME/sshd.pid" \
  -o UsePAM=no \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -h "$HOME/.ssh/ssh_host_ed25519_key"
exec herdr --session agent server
