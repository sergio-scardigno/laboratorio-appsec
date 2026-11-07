#!/usr/bin/env bash
# Instala la web del laboratorio como servicio de systemd. Ejecutar como root, una vez:
#   bash scripts/install-web-service.sh <usuario>
# Desde el host de Proxmox:
#   pct exec <id> -- bash /ruta/a/appsec-lab/scripts/install-web-service.sh <usuario>
# Se puede repetir para actualizarlo.
set -euo pipefail

fail() { echo "ERROR: $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "ejecuta este script como root."
target_user="${1:-}"
[[ -n "${target_user}" && "${target_user}" != "root" ]] || fail "indica el usuario: bash $0 <usuario>"
id "${target_user}" >/dev/null 2>&1 || fail "no existe el usuario ${target_user}."
id -nG "${target_user}" | tr ' ' '\n' | grep -qx docker || fail "${target_user} no está en el grupo docker. Ejecuta antes scripts/bootstrap-host.sh."

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -x "${root}/.venv/bin/lab" ]] || fail "falta ${root}/.venv/bin/lab: ejecuta antes make setup."
[[ -f "${root}/.env" ]] || fail "falta ${root}/.env: ejecuta antes make setup."

sed -e "s|TU_USUARIO|${target_user}|g" -e "s|/ruta/a/appsec-lab|${root}|g" \
  "${root}/deploy/appsec-lab-web.service" > /etc/systemd/system/appsec-lab-web.service
systemctl daemon-reload
systemctl enable --now appsec-lab-web
systemctl restart appsec-lab-web

sleep 3
systemctl is-active --quiet appsec-lab-web || {
  journalctl -u appsec-lab-web -n 25 --no-pager >&2 || true
  fail "el servicio no arrancó."
}
echo "Servicio activo. Solo escucha en 127.0.0.1:8000."
echo "Para ver el enlace de acceso: ${root}/.venv/bin/lab web-url"
