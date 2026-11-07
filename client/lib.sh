# Funciones compartidas por el hook pre-push y el comando appsec-gate.
# Compatible con bash 3.2 (macOS) y con el bash de Git for Windows.

APPSEC_HOME="${APPSEC_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
APPSEC_PATTERNS="$APPSEC_HOME/agent-patterns.txt"
APPSEC_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/appsec-gate"

appsec_say() { printf 'appsec-gate: %s\n' "$*" >&2; }

appsec_config() {
  local value
  value="$(git config --get "$1" 2>/dev/null)" || value=""
  printf '%s' "${value:-$2}"
}

appsec_expand() {
  case "$1" in
    "~/"*) printf '%s' "$HOME/${1#\~/}" ;;
    *) printf '%s' "$1" ;;
  esac
}

# Conexión con el laboratorio: clave dedicada, sin contraseñas ni preguntas.
appsec_ssh() {
  local host key ssh_cmd
  host="$(appsec_config appsec.host "")"
  if [ -z "$host" ]; then
    appsec_say "falta appsec.host: ejecuta client/install.sh --host usuario@laboratorio"
    return 255
  fi
  key="$(appsec_expand "$(appsec_config appsec.sshKey "~/.ssh/appsec_gate")")"
  ssh_cmd="$(appsec_config appsec.ssh ssh)"
  # shellcheck disable=SC2086 # appsec.ssh puede llevar argumentos (pruebas)
  $ssh_cmd -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 \
    -o ServerAliveInterval=30 -o StrictHostKeyChecking=accept-new "$host" "$@"
}

# Nombre del repo para su línea base: dueño-repo, a partir de la URL del remoto
# (https://github.com/dueño/repo.git, git@github.com:dueño/repo.git o una ruta).
appsec_repo_name() {
  local url="$1" repo owner name
  url="${url%/}"
  url="${url%.git}"
  repo="${url##*/}"
  owner="${url%/*}"
  [ "$owner" = "$url" ] && owner=""
  owner="${owner##*/}"
  owner="${owner##*:}"
  name="${owner:+$owner-}$repo"
  name="$(printf '%s' "$name" | LC_ALL=C tr -c 'A-Za-z0-9._-' '-' | sed -e 's/^[^A-Za-z0-9]*//' -e 's/\.\.*/./g')"
  name="$(printf '%s' "$name" | cut -c1-100)"
  printf '%s' "${name:-repo}"
}

appsec_is_zero() { case "$1" in *[!0]*) return 1 ;; *) return 0 ;; esac; }

# Commits nuevos que este push publicaría: los que no tiene el remoto.
appsec_new_commits() {
  local local_sha="$1" remote_sha="$2"
  if ! appsec_is_zero "$remote_sha" && git cat-file -e "$remote_sha^{commit}" 2>/dev/null; then
    git rev-list "$remote_sha..$local_sha"
  else
    git rev-list "$local_sha" --not --remotes
  fi
}

# Expresión regular de las rutas prohibidas, desde agent-patterns.txt.
appsec_path_regex() {
  sed -n 's/^path:[[:space:]]*//p' "$APPSEC_PATTERNS" | sed 's/[[:space:]]*$//' | while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    entry="$(printf '%s' "$entry" | sed -e 's/[][\.^$+?(){}|]/\\&/g' -e 's/\*/[^\/]*/g')"
    printf '(^|/)%s(/|$)\n' "$entry"
  done
}

appsec_list() { sed -n "s/^$1:[[:space:]]*//p" "$APPSEC_PATTERNS" | sed 's/[[:space:]]*$//' | grep -v '^$'; }

appsec_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# Política de autoría para una lista de commits (uno por línea en stdin) y el
# árbol que se sube. Escribe los problemas en stdout; sale con 1 si hay alguno.
appsec_check_policy() {
  local tip="$1" signers owners work commits problems=0
  signers="$(appsec_expand "$(appsec_config gpg.ssh.allowedSignersFile "")")"
  owners="$(git config --get-all appsec.ownerEmail 2>/dev/null | tr '[:upper:]' '[:lower:]')"
  work="$(mktemp -d "${TMPDIR:-/tmp}/appsec-policy.XXXXXX")"
  commits="$work/commits"
  cat >"$commits"

  if [ -z "$owners" ]; then
    echo "No hay emails del propietario (appsec.ownerEmail). Ejecuta client/install.sh."
    problems=1
  fi
  if [ -z "$signers" ] || [ ! -s "$signers" ]; then
    echo "No hay archivo de firmantes (gpg.ssh.allowedSignersFile). Ejecuta client/install.sh."
    problems=1
  fi

  appsec_path_regex >"$work/paths"
  appsec_list name | tr '[:upper:]' '[:lower:]' >"$work/names"
  appsec_list phrase | tr '[:upper:]' '[:lower:]' >"$work/phrases"

  local c short sig ae ce msg trailers
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    short="$(git rev-parse --short "$c")"
    if [ -n "$signers" ] && [ -s "$signers" ]; then
      sig="$(git -c gpg.ssh.allowedSignersFile="$signers" log -1 --format='%G?' "$c" 2>/dev/null)"
      if [ "$sig" != "G" ]; then
        echo "$short: sin firma válida del propietario (estado $sig). Firma con: git commit --amend -S, o git rebase --exec 'git commit --amend --no-edit -S' <base>"
        problems=1
      fi
    fi
    ae="$(appsec_lower "$(git log -1 --format='%ae' "$c")")"
    ce="$(appsec_lower "$(git log -1 --format='%ce' "$c")")"
    if [ -n "$owners" ]; then
      printf '%s\n' "$owners" | grep -qxF -- "$ae" || { echo "$short: el autor <$ae> no es el propietario"; problems=1; }
      printf '%s\n' "$owners" | grep -qxF -- "$ce" || { echo "$short: quien hizo el commit <$ce> no es el propietario"; problems=1; }
    fi
    msg="$(git log -1 --format='%B' "$c" | tr '[:upper:]' '[:lower:]')"
    if printf '%s\n' "$msg" | grep -qiF -f "$work/phrases"; then
      echo "$short: el mensaje tiene una marca de agente ($(printf '%s\n' "$msg" | grep -iF -o -f "$work/phrases" | head -1)). Quítala con git commit --amend o git rebase -i"
      problems=1
    fi
    # Cualquier coautor que no sea el propietario.
    printf '%s\n' "$msg" | sed -n 's/^[[:space:]]*co-authored-by:[[:space:]]*//p' | while IFS= read -r who; do
      email="$(printf '%s' "$who" | sed -n 's/.*<\([^>]*\)>.*/\1/p')"
      if [ -z "$owners" ] || ! printf '%s\n' "$owners" | grep -qxF -- "$email"; then
        echo "$short: coautor no permitido: $who"
      fi
    done >>"$work/coauthors"
    # Otros trailers (Assisted-by, Generated-by, Signed-off-by...) que nombran a un agente.
    trailers="$(printf '%s\n' "$msg" | grep -E '^[[:space:]]*[a-z][a-z-]*-by:' || true)"
    if [ -n "$trailers" ] && printf '%s\n' "$trailers" | grep -qiwF -f "$work/names"; then
      echo "$short: trailer de agente: $(printf '%s\n' "$trailers" | grep -iwF -f "$work/names" | head -1)"
      problems=1
    fi
  done <"$commits"
  if [ -s "$work/coauthors" ]; then
    cat "$work/coauthors"
    problems=1
  fi

  # Carpetas y archivos de agentes: en lo que se sube y en cualquier commit nuevo.
  if [ -s "$work/paths" ]; then
    {
      git -c core.quotepath=false ls-tree -r --name-only --full-tree "$tip"
      [ -s "$commits" ] && git -c core.quotepath=false log --no-walk=unsorted --format= --name-only --no-renames --stdin <"$commits"
    } 2>/dev/null | grep -Ei -f "$work/paths" | sort -u >"$work/hits" || true
    if [ -s "$work/hits" ]; then
      echo "Archivos de agentes en lo que se sube o en sus commits nuevos (quítalos también del historial con git rebase -i):"
      sed 's/^/  /' "$work/hits" | head -20
      problems=1
    fi
  fi

  rm -rf "$work"
  return "$problems"
}
