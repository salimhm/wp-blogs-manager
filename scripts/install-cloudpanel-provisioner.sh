#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi

if [[ $# -ne 1 || ! -f $1 ]]; then
  echo "Usage: sudo $0 /path/to/id_ed25519.pub" >&2
  exit 1
fi

for command in clpctl wp runuser visudo; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
wrapper_source="$script_dir/wp-manager-cloudpanel"
if [[ ! -f $wrapper_source ]]; then
  echo "Wrapper not found next to installer: $wrapper_source" >&2
  exit 1
fi

public_key=$(tr -d '\r\n' < "$1")
if [[ ! $public_key =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp)\  ]]; then
  echo "The supplied file is not a supported SSH public key." >&2
  exit 1
fi

provision_user=wp-provisioner
if ! id "$provision_user" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$provision_user"
fi

install -o root -g root -m 0755 "$wrapper_source" /usr/local/sbin/wp-manager-cloudpanel
install -d -o "$provision_user" -g "$provision_user" -m 0700 "/home/$provision_user/.ssh"

authorized_keys="/home/$provision_user/.ssh/authorized_keys"
forced_key="restrict,command=\"sudo -n /usr/local/sbin/wp-manager-cloudpanel\" $public_key"
temporary_keys=$(mktemp)
if [[ -f $authorized_keys ]]; then
  grep -vF "$public_key" "$authorized_keys" > "$temporary_keys" || true
fi
printf '%s\n' "$forced_key" >> "$temporary_keys"
install -o "$provision_user" -g "$provision_user" -m 0600 "$temporary_keys" "$authorized_keys"
rm -f "$temporary_keys"

sudoers_file=/etc/sudoers.d/wp-manager-cloudpanel
temporary_sudoers=$(mktemp)
printf '%s\n' \
  "$provision_user ALL=(root) NOPASSWD: /usr/local/sbin/wp-manager-cloudpanel" \
  > "$temporary_sudoers"
chmod 0440 "$temporary_sudoers"
visudo -cf "$temporary_sudoers"
install -o root -g root -m 0440 "$temporary_sudoers" "$sudoers_file"
rm -f "$temporary_sudoers"

install -d -o root -g root -m 0700 /var/lib/wp-manager-provisioning

echo "CloudPanel provisioner installed for $provision_user."
echo "The SSH key is restricted to the provisioning wrapper only."
