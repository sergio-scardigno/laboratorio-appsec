#!/usr/bin/env bash
# Prepara el host del laboratorio (Ubuntu 24.04, VM o contenedor LXC).
# Ejecutar como root, indicando el usuario que usará Docker:
#   bash scripts/bootstrap-host.sh <usuario>
# Desde el host de Proxmox:
#   pct exec <id> -- bash /ruta/a/appsec-lab/scripts/bootstrap-host.sh <usuario>
# Se puede repetir sin efectos adversos.
set -euo pipefail

MIN_DISK_GB=30
MIN_MAP_COUNT=524288

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "ejecuta este script como root."

target_user="${1:-${SUDO_USER:-}}"
[[ -n "${target_user}" && "${target_user}" != "root" ]] \
  || fail "indica el usuario: bash scripts/bootstrap-host.sh <usuario>"
id "${target_user}" >/dev/null 2>&1 || fail "no existe el usuario ${target_user}."

# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID}" == "ubuntu" ]] || fail "pensado para Ubuntu; detectado: ${PRETTY_NAME}."

virt="$(systemd-detect-virt 2>/dev/null || true)"
echo "==> Host: ${PRETTY_NAME}, virtualización: ${virt:-ninguna}"

disk_gb="$(df --output=size -BG / | tail -1 | tr -dc '0-9')"
[[ "${disk_gb}" -ge "${MIN_DISK_GB}" ]] \
  || fail "el disco tiene ${disk_gb} GB y hacen falta al menos ${MIN_DISK_GB}. En Proxmox: pct resize <id> rootfs 50G"

if [[ "${virt}" == "lxc" ]]; then
  echo "AVISO: Docker dentro de LXC reduce el aislamiento frente a una VM."
  # En Proxmox, una llamada a keyctl sin la opción keyctl=1 devuelve ENOSYS.
  if ! python3 -I -c "
import ctypes, errno, sys
libc = ctypes.CDLL(None, use_errno=True)
result = libc.syscall(250, 0, -3, 0, 0, 0)
sys.exit(1 if result < 0 and ctypes.get_errno() == errno.ENOSYS else 0)
"; then
    fail "falta keyctl. En Proxmox: pct set <id> --features nesting=1,keyctl=1 y reinicia el contenedor."
  fi
  grep -q '/dev/.lxc' /proc/self/mountinfo \
    || fail "falta nesting. En Proxmox: pct set <id> --features nesting=1,keyctl=1 y reinicia el contenedor."
fi

export DEBIAN_FRONTEND=noninteractive

echo "==> Paquetes base"
apt-get update -y
apt-get install -y ca-certificates curl git make rsync python3-venv

echo "==> Repositorio oficial de Docker"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${VERSION_CODENAME}
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
  || echo "AVISO: apt informó de un error; se comprueba Docker más abajo."

echo "==> Rotación de logs de Docker"
if [[ ! -f /etc/docker/daemon.json ]]; then
  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
EOF
fi
systemctl enable docker >/dev/null 2>&1 || true
systemctl restart docker || true

echo "==> Parámetros del kernel para Elasticsearch (SonarQube)"
current_map_count="$(sysctl -n vm.max_map_count)"
if [[ "${current_map_count}" -ge "${MIN_MAP_COUNT}" ]]; then
  echo "vm.max_map_count=${current_map_count}: suficiente"
elif [[ "${virt}" == "lxc" ]]; then
  # En un LXC este valor pertenece al kernel del host.
  fail "vm.max_map_count=${current_map_count}. En el host de Proxmox: sysctl -w vm.max_map_count=${MIN_MAP_COUNT}"
else
  echo "vm.max_map_count=${MIN_MAP_COUNT}" > /etc/sysctl.d/99-appsec-lab.conf
  sysctl --system >/dev/null
fi

echo "==> Acceso a Docker para ${target_user}"
# Pertenecer al grupo docker equivale a ser root en este host: por eso se dedica
# exclusivamente al laboratorio.
usermod -aG docker "${target_user}"

echo "==> Prueba real de Docker"
if ! docker run --rm hello-world >/tmp/appsec-lab-docker-test.log 2>&1; then
  echo "--- salida de docker run ---" >&2
  cat /tmp/appsec-lab-docker-test.log >&2
  echo "--- últimos logs del servicio ---" >&2
  journalctl -u docker -n 25 --no-pager >&2 || true
  fail "Docker no puede arrancar contenedores aquí."
fi

echo
echo "Listo."
docker --version
docker compose version
echo "Storage driver: $(docker info --format '{{.Driver}}')"
echo "Prueba hello-world: correcta"
echo "${target_user} debe abrir una sesión nueva para usar Docker sin sudo."
