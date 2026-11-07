#!/usr/bin/env bash
# Pruebas del hook pre-push con repos, claves y un HOME temporales.
# El laboratorio se simula con un "ssh" falso salvo que se pase LAB_REAL=1.
#
#   bash client/tests/test-policy.sh
set -u

CLIENT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/appsec-client-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

export HOME="$TMP/home"
export GIT_CONFIG_NOSYSTEM=1
export XDG_CACHE_HOME="$TMP/cache"
unset GIT_CONFIG_GLOBAL APPSEC_HOME
mkdir -p "$HOME/.ssh"
OWNER=owner@example.com

ssh-keygen -q -t ed25519 -N "" -C owner -f "$HOME/.ssh/owner_sign"
ssh-keygen -q -t ed25519 -N "" -C other -f "$HOME/.ssh/other_sign"
git config --global user.name "Owner"
git config --global user.email "$OWNER"
git config --global init.defaultBranch main
bash "$CLIENT/install.sh" --email "$OWNER" --email 1+owner@users.noreply.github.com \
  --signing-key "$HOME/.ssh/owner_sign.pub" --host test@lab >/dev/null || { echo "install.sh falló"; exit 1; }

# ssh falso: responde como el laboratorio según $FAKE_STATUS y guarda lo recibido.
cat >"$TMP/fake-ssh" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do case "$1" in -i|-o) shift 2 ;; *) break ;; esac; done
shift  # host
case "$1" in
  gate)
    cat >"$FAKE_DIR/received.tar"
    echo "GATE-RUN: 20261107-120000-abcd"
    exit "${FAKE_STATUS:-0}" ;;
  report) echo "<html>informe</html>" ;;
esac
EOF
chmod +x "$TMP/fake-ssh"
export FAKE_DIR="$TMP"
if [ "${LAB_REAL:-0}" != 1 ]; then
  git config --global appsec.ssh "$TMP/fake-ssh"
fi

git init -q --bare "$TMP/remote.git"
git clone -q "$TMP/remote.git" "$TMP/work" 2>/dev/null
cd "$TMP/work" || exit 1
echo "hola" >README.md
git add README.md
git commit -q -m "inicio"
FAKE_STATUS=0 git push -q origin main 2>/dev/null || { echo "el push inicial falló"; exit 1; }

pass=0
fail=0
expect() {  # expect <bloquea|pasa> <descripción> [FAKE_STATUS]
  local want="$1" what="$2" out
  out="$(FAKE_STATUS="${3:-0}" git push origin HEAD:main 2>&1)"
  local status=$?
  if { [ "$want" = bloquea ] && [ $status -ne 0 ]; } || { [ "$want" = pasa ] && [ $status -eq 0 ]; }; then
    pass=$((pass + 1)); echo "ok    $want: $what"
    [ "$want" = bloquea ] && printf '%s\n' "$out" | grep -m1 -E '^  [^ ]|BLOQUEADO' | sed 's/^ */        → /'
  else
    fail=$((fail + 1)); echo "FALLO $want: $what"; printf '%s\n' "$out" | sed 's/^/      /'
  fi
  git fetch -q origin
  git reset -q --hard origin/main
}

commit() { echo "$RANDOM" >>"${FILE:-app.txt}"; git add -A; git commit -q "$@"; }

commit -m "cambio firmado"
expect pasa "commit firmado y limpio"

commit -m "sin firma" --no-gpg-sign
expect bloquea "commit sin firma"

git -c user.signingkey="$HOME/.ssh/other_sign.pub" commit -q --allow-empty -m "otra clave"
expect bloquea "commit firmado con otra clave"

commit -m "autor ajeno" --author "Otra <otra@example.com>"
expect bloquea "autor que no es el propietario"

commit -m "con ayuda" -m "Co-Authored-By: Claude Opus <noreply@anthropic.com>"
expect bloquea "coautor Claude"

commit -m "con cursor" -m "Co-authored-by: Cursor Agent <cursoragent@cursor.com>"
expect bloquea "coautor Cursor"

commit -m "persona" -m "Co-authored-by: Pepa <pepa@example.com>"
expect bloquea "coautor humano que no es el propietario"

commit -m "propio" -m "Co-authored-by: Owner <$OWNER>"
expect pasa "coautor que es el propietario"

commit -m "asistido" -m "Assisted-by: GitHub Copilot"
expect bloquea "trailer Assisted-by de un agente"

commit -m "revisado" -m "Reviewed-by: Rooney Cursory <$OWNER>"
expect pasa "palabras que solo contienen un nombre de agente"

commit -m "frase" -m "🤖 Generated with [Claude Code](https://claude.com/claude-code)"
expect bloquea "frase de Claude Code en el mensaje"

mkdir -p .cursor && echo x >.cursor/rules && git add -f .cursor && git commit -q -m "reglas"
git rm -q -r .cursor && git commit -q -m "quita reglas"
expect bloquea "carpeta .cursor añadida y borrada en el historial nuevo"

echo x >CLAUDE.md && git add -f CLAUDE.md && git commit -q -m "memoria"
expect bloquea "CLAUDE.md en el árbol"

mkdir -p sub/.aider.tags.cache.v3 && echo x >sub/.aider.tags.cache.v3/a && git add -f sub && git commit -q -m "aider"
expect bloquea ".aider* en una subcarpeta"

mkdir -p .github && echo x >.github/copilot-instructions.md && git add -f .github && git commit -q -m "copilot"
expect bloquea ".github/copilot-instructions.md"

echo x >claude-notes.txt && git add claude-notes.txt && git commit -q -m "notas"
expect pasa "un archivo que solo contiene 'claude' en el nombre"

if [ "${LAB_REAL:-0}" != 1 ]; then
  commit -m "hallazgo"
  expect bloquea "el laboratorio encuentra algo (exit 1)" 1
  commit -m "sin conexión"
  expect bloquea "el laboratorio no responde (exit 255)" 255
  commit -m "envío"
  FAKE_STATUS=0 git push -q origin HEAD:main 2>/dev/null
  if tar -tf "$TMP/received.tar" | grep -qx ".lab-history/commits.patch" && tar -tf "$TMP/received.tar" | grep -qx "app.txt"; then
    pass=$((pass + 1)); echo "ok    envía el árbol y el parche de los commits nuevos"
  else
    fail=$((fail + 1)); echo "FALLO no envía el árbol y el parche"
  fi
  git fetch -q origin; git reset -q --hard origin/main
  git config appsec.scan false
  commit -m "sin análisis" --no-gpg-sign
  expect bloquea "appsec.scan=false no salta la política"
  git config --unset appsec.scan
fi

grep -q "^\.claude$" "$HOME/.config/git/ignore" && { pass=$((pass + 1)); echo "ok    gitignore global con .claude"; } \
  || { fail=$((fail + 1)); echo "FALLO falta .claude en el gitignore global"; }

echo
echo "$pass correctas, $fail fallidas"
[ "$fail" -eq 0 ]
