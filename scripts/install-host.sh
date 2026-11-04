#!/bin/bash
# Homelab-Drift: prepare a host for (read-only) monitoring. Run as root on the target host.
#
#   sudo ./install-host.sh "ssh-ed25519 AAAA… homelab-drift@controller"   key from the controller: /var/lib/homelab-drift/.ssh/id_ed25519.pub
#   sudo ./install-host.sh "<key>" --from 192.0.2.10                       key only valid from this address (recommended)
#   sudo ./install-host.sh --remove                                        remove everything again
#
# Creates: user "drift" (no password, no interactive login), the gate under /usr/local/lib/homelab-drift,
# /etc/sudoers.d/homelab-drift (only the read-only gate verbs) and a restricted authorized_keys entry
# (forced command, no PTY, no forwarding). Idempotent.
set -euo pipefail
LIB=/usr/local/lib/homelab-drift
USER_=drift
HOME_=/var/lib/drift
SUDOERS=/etc/sudoers.d/homelab-drift
VERBS="ping system docker ports nginx cron systemd storage tailscale"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo "Please run as root (sudo)."; exit 1; }

if [[ "${1-}" == "--remove" ]]; then
  rm -f "$SUDOERS"
  rm -rf "$LIB"
  id "$USER_" >/dev/null 2>&1 && userdel -r "$USER_" 2>/dev/null || true
  echo "Homelab-Drift access removed."
  exit 0
fi

KEY="${1-}"; FROM=""
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM="$2"; shift 2 ;;
    *) echo "Unknown option $1"; exit 2 ;;
  esac
done
[[ "$KEY" =~ ^ssh-(ed25519|rsa)\ [A-Za-z0-9+/=]+ ]] || { echo "The first argument must be the public SSH key (ssh-ed25519 …)."; exit 2; }

echo "==> Gate -> $LIB"
install -d -o root -g root -m 755 "$LIB"
install -o root -g root -m 755 "$SRC/gate/drift-gate" "$LIB/drift-gate"
install -o root -g root -m 755 "$SRC/gate/drift-ssh" "$LIB/drift-ssh"

echo "==> User $USER_"
if ! id "$USER_" >/dev/null 2>&1; then
  useradd --system --home-dir "$HOME_" --create-home --shell /bin/bash --comment "Homelab-Drift (read-only)" "$USER_"
fi
# "*" = no password possible, but the account is not locked (otherwise sshd may reject keys too, depending on PAM)
usermod -p '*' "$USER_"
# never in the docker group: it is root-equivalent
gpasswd -d "$USER_" docker >/dev/null 2>&1 || true

echo "==> sudoers $SUDOERS"
TMP=$(mktemp)
{
  echo "# Homelab-Drift: user $USER_ may run exactly these read-only gate verbs as root, nothing else."
  echo "Defaults:$USER_ !requiretty, !lecture, env_reset"
  printf "%s ALL=(root) NOPASSWD:" "$USER_"
  first=1
  for v in $VERBS; do
    [[ $first -eq 1 ]] && first=0 || printf ","
    printf " %s/drift-gate %s" "$LIB" "$v"
  done
  echo
} > "$TMP"
visudo -cf "$TMP" >/dev/null || { echo "sudoers check failed"; cat "$TMP"; rm -f "$TMP"; exit 1; }
install -o root -g root -m 440 "$TMP" "$SUDOERS"
rm -f "$TMP"

echo "==> authorized_keys"
OPTS="command=\"$LIB/drift-ssh\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc"
[[ -n "$FROM" ]] && OPTS="from=\"$FROM\",$OPTS"
install -d -o "$USER_" -g "$USER_" -m 700 "$HOME_/.ssh"
AK="$HOME_/.ssh/authorized_keys"
KEYBODY=$(echo "$KEY" | awk '{print $2}')
touch "$AK"
grep -v -F "$KEYBODY" "$AK" > "$AK.new" || true
echo "$OPTS $KEY" >> "$AK.new"
mv "$AK.new" "$AK"
chown "$USER_:$USER_" "$AK"; chmod 600 "$AK"

# only report sshd restrictions that would block access (sshd itself is never changed)
if command -v sshd >/dev/null 2>&1; then
  CFG=$(sshd -T 2>/dev/null || true)
  if echo "$CFG" | grep -qiE '^(allowusers|allowgroups) '; then
    echo "NOTE: sshd has AllowUsers/AllowGroups set. '$USER_' must be allowed there:"
    echo "$CFG" | grep -iE '^(allowusers|allowgroups) '
  fi
fi

echo "==> Self-test"
sudo -u "$USER_" sudo -n "$LIB/drift-gate" ping
if sudo -u "$USER_" sudo -n "$LIB/drift-gate" reboot >/dev/null 2>&1; then
  echo "ERROR: the gate did not reject 'reboot'"; exit 1
fi
echo "Gate rejects unlisted commands: ok"
echo "Done. On the controller add the host to /etc/homelab-drift/config.yaml and run 'sudo homelab-drift check'."
