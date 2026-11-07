#!/usr/bin/env bash
# Comando forzado de la clave SSH de la puerta antes del push.
#
# En ~/.ssh/authorized_keys del laboratorio:
#   command="/ruta/a/appsec-lab/scripts/gate-ssh.sh",restrict ssh-ed25519 AAAA... appsec-gate
#
# Solo acepta estas órdenes (en SSH_ORIGINAL_COMMAND):
#   gate <repo>                 lee un tar por stdin y lo analiza
#   report <run_id>             devuelve el informe HTML de un análisis de la puerta
#   accept <repo> <run_id>      acepta lo que bloqueó; el motivo llega por stdin
#   list <repo>                 muestra la línea base
set -euo pipefail
umask 077

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$LAB_DIR/.venv/bin/lab"
cd "$LAB_DIR"

repo_re='^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'
run_re='^[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$'

refuse() {
  echo "appsec-gate: $1" >&2
  exit 3
}

# Sin expansión de comodines ni de variables: solo se separa por espacios.
set -f
read -r -a args <<<"${SSH_ORIGINAL_COMMAND:-}"
set +f
verb="${args[0]:-}"

check_repo() { [[ "$1" =~ $repo_re && "$1" != *..* ]] || refuse "nombre de repo no válido"; }
check_run() { [[ "$1" =~ $run_re ]] || refuse "id de análisis no válido"; }

# Docker: las sesiones SSH ya tienen el grupo; sg solo si aún no.
run_lab() {
  if id -nG | tr ' ' '\n' | grep -qx docker; then
    "$LAB" "$@"
  else
    sg docker -c "$(printf '%q ' "$LAB" "$@")"
  fi
}

case "$verb" in
  gate)
    [[ ${#args[@]} -eq 2 ]] || refuse "uso: gate <repo>"
    check_repo "${args[1]}"
    run_lab gate run --name "${args[1]}" --stdin
    ;;
  report)
    [[ ${#args[@]} -eq 2 ]] || refuse "uso: report <run_id>"
    check_run "${args[1]}"
    "$LAB" gate report --run "${args[1]}"
    ;;
  accept)
    [[ ${#args[@]} -eq 3 ]] || refuse "uso: accept <repo> <run_id> (motivo por stdin)"
    check_repo "${args[1]}"
    check_run "${args[2]}"
    "$LAB" gate accept --name "${args[1]}" --run "${args[2]}" --reason -
    ;;
  list)
    [[ ${#args[@]} -eq 2 ]] || refuse "uso: list <repo>"
    check_repo "${args[1]}"
    "$LAB" gate list --name "${args[1]}"
    ;;
  *)
    refuse "orden no permitida. Esta clave solo sirve para la puerta antes del push"
    ;;
esac
