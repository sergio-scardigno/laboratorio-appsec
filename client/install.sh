#!/usr/bin/env bash
# Instala la puerta antes del push en tu compu (Linux, macOS o Git Bash en Windows).
#
#   bash client/install.sh --host usuario@laboratorio --email tu@correo --email 12345+usuario@users.noreply.github.com
#
# Opciones:
#   --email EMAIL        email del propietario; repítelo para cada uno (obligatorio)
#   --host USUARIO@HOST  laboratorio, por SSH (obligatorio)
#   --lab-dir RUTA       carpeta del laboratorio en ese host (por defecto /home/USUARIO/appsec-lab)
#   --signing-key PUB    clave pública SSH con la que firmas (por defecto ~/.ssh/id_ed25519.pub,
#                        y si no existe se crea ~/.ssh/appsec_signing)
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# En Git Bash (Windows), git.exe no entiende rutas /c/...: se guardan como C:/...
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
DEST="${APPSEC_HOME:-$HOME/.config/appsec-gate}"
host=""
lab_dir=""
signing_pub=""
emails=""

while [ $# -gt 0 ]; do
  case "$1" in
    --email) emails="$emails $(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"; shift 2 ;;
    --host) host="$2"; shift 2 ;;
    --lab-dir) lab_dir="$2"; shift 2 ;;
    --signing-key) signing_pub="$2"; shift 2 ;;
    *) echo "Opción desconocida: $1" >&2; exit 2 ;;
  esac
done
[ -n "$emails" ] || { echo "Falta --email: el email (o los emails) de tu cuenta de GitHub" >&2; exit 2; }
[ -n "$host" ] || { echo "Falta --host: usuario@host del laboratorio" >&2; exit 2; }
lab_dir="${lab_dir:-/home/${host%@*}/appsec-lab}"

echo "1. Copiando la puerta a $DEST"
mkdir -p "$DEST/hooks" "$DEST/bin"
cp "$SRC/lib.sh" "$SRC/agent-patterns.txt" "$DEST/"
cp "$SRC/hooks/pre-push" "$DEST/hooks/pre-push"
cp "$SRC/bin/appsec-gate" "$DEST/bin/appsec-gate"
chmod +x "$DEST/hooks/pre-push" "$DEST/bin/appsec-gate"

previous="$(git config --global --get core.hooksPath || true)"
if [ -n "$previous" ] && [ "$previous" != "$DEST/hooks" ] && [ "$previous" != "$(native "$DEST/hooks")" ]; then
  echo "   Aviso: tenías core.hooksPath=$previous; los hooks globales de ahí dejan de ejecutarse."
fi
git config --global core.hooksPath "$(native "$DEST/hooks")"
git config --global alias.gate "!\"$DEST/bin/appsec-gate\""
git config --global appsec.host "$host"
git config --global appsec.sshKey "~/.ssh/appsec_gate"
git config --global --unset-all appsec.ownerEmail 2>/dev/null || true
for email in $emails; do git config --global --add appsec.ownerEmail "$email"; done

echo "2. Firma de commits con SSH"
mkdir -p "$HOME/.ssh"
if [ -z "$signing_pub" ]; then
  if [ -f "$HOME/.ssh/id_ed25519.pub" ]; then
    signing_pub="$HOME/.ssh/id_ed25519.pub"
  else
    signing_pub="$HOME/.ssh/appsec_signing.pub"
    [ -f "$signing_pub" ] || ssh-keygen -q -t ed25519 -C "firma de commits" -f "${signing_pub%.pub}"
  fi
fi
[ -f "$signing_pub" ] || { echo "No existe $signing_pub" >&2; exit 2; }
principals="$(printf '%s' "$emails" | sed 's/^ //; s/ /,/g')"
printf '%s namespaces="git" %s\n' "$principals" "$(cut -d' ' -f1,2 "$signing_pub")" >"$DEST/allowed_signers"
git config --global gpg.format ssh
git config --global user.signingkey "$(native "$signing_pub")"
git config --global gpg.ssh.allowedSignersFile "$(native "$DEST/allowed_signers")"
git config --global commit.gpgsign true
git config --global tag.gpgsign true
current_email="$(git config --global --get user.email || true)"
case " $emails " in
  *" $(printf '%s' "$current_email" | tr '[:upper:]' '[:lower:]') "*) ;;
  *) echo "   Aviso: tu user.email ($current_email) no está entre los emails del propietario; tus commits se bloquearían." ;;
esac

echo "3. Carpetas y archivos de agentes en tu gitignore global"
excludes="$(git config --global --get core.excludesFile || true)"
if [ -z "$excludes" ]; then
  excludes="$HOME/.config/git/ignore"
  git config --global core.excludesFile "$(native "$excludes")"
fi
case "$excludes" in "~/"*) excludes="$HOME/${excludes#\~/}" ;; esac
if command -v cygpath >/dev/null 2>&1; then excludes="$(cygpath -u "$excludes")"; fi
mkdir -p "$(dirname "$excludes")"
touch "$excludes"
tmp="$(mktemp)"
sed '/^# >>> appsec-gate/,/^# <<< appsec-gate/d' "$excludes" >"$tmp"
{
  echo "# >>> appsec-gate: archivos de agentes (lo gestiona client/install.sh)"
  sed -n 's/^path:[[:space:]]*//p' "$SRC/agent-patterns.txt" | sed 's/[[:space:]]*$//' | while IFS= read -r entry; do
    case "$entry" in */*) echo "**/$entry" ;; *) echo "$entry" ;; esac
  done
  echo "# <<< appsec-gate"
} >>"$tmp"
mv "$tmp" "$excludes"

echo "4. Clave para hablar con el laboratorio"
if [ ! -f "$HOME/.ssh/appsec_gate" ]; then
  # Sin contraseña: el hook no puede preguntarla. En el laboratorio solo sirve para la puerta.
  ssh-keygen -q -t ed25519 -N "" -C "appsec-gate" -f "$HOME/.ssh/appsec_gate"
fi

cat <<EOF

Listo. Te faltan tres pasos:

a) En el laboratorio, agrega esta línea a ~/.ssh/authorized_keys del usuario ${host%@*}:

command="$lab_dir/scripts/gate-ssh.sh",restrict $(cut -d' ' -f1,2 "$HOME/.ssh/appsec_gate.pub") appsec-gate

   O, en un solo paso: ssh $host $lab_dir/scripts/add-gate-key.sh < ~/.ssh/appsec_gate.pub

b) En GitHub, sube tu clave de firma como "Signing key" (Settings > SSH and GPG keys):
   $signing_pub
   Con la CLI de GitHub: gh ssh-key add "$signing_pub" --type signing --title "firma de commits"

c) Opcional, para que GitHub también lo exija: en cada repo, Settings > Rules o Branches,
   activa "Require signed commits" en la rama principal.

Prueba la conexión con: git gate list   (dentro de un repo con remoto)
EOF
