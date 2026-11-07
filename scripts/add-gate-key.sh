#!/usr/bin/env bash
# Autoriza en este laboratorio la clave de la puerta antes del push, limitada a
# scripts/gate-ssh.sh (sin shell, túneles ni reenvíos). Lee la clave pública por stdin:
#
#   ssh usuario@laboratorio appsec-lab/scripts/add-gate-key.sh < ~/.ssh/appsec_gate.pub
set -euo pipefail
umask 077

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
read -r type key _ || true
[ "${type:-}" = "ssh-ed25519" ] && [[ "${key:-}" =~ ^[A-Za-z0-9+/]+=*$ ]] || {
  echo "No es una clave pública ssh-ed25519" >&2
  exit 2
}
mkdir -p "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
if grep -qF "$key" "$HOME/.ssh/authorized_keys"; then
  echo "Esa clave ya estaba autorizada"
  exit 0
fi
printf 'command="%s/scripts/gate-ssh.sh",restrict %s %s appsec-gate\n' "$LAB_DIR" "$type" "$key" >>"$HOME/.ssh/authorized_keys"
echo "Clave autorizada solo para la puerta antes del push"
