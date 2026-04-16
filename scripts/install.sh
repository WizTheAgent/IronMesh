#!/usr/bin/env bash
# IronMesh — one-line installer
#
# Usage (from a checkout):
#     ./scripts/install.sh
#
# Usage (remote, once published):
#     curl -fsSL https://raw.githubusercontent.com/WizTheAgent/IronMesh/main/scripts/install.sh | bash
#
# Options (environment variables):
#   IRONMESH_PREFIX      — install prefix (default: $HOME/.local/share/ironmesh)
#   IRONMESH_PYTHON      — Python interpreter (default: python3)
#   IRONMESH_NO_SYSTEMD  — set to 1 to skip systemd user service install
#   IRONMESH_NO_RNS      — set to 1 to skip rns optional extras
#   IRONMESH_SRC         — source directory (default: script parent)

set -euo pipefail

PREFIX="${IRONMESH_PREFIX:-$HOME/.local/share/ironmesh}"
PYTHON_BIN="${IRONMESH_PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${IRONMESH_SRC:-$(cd "$SCRIPT_DIR/.." && pwd)}"
VENV="$PREFIX/venv"

msg()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; }

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ "$(uname)" = "Darwin" ]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

install_python_if_missing() {
    if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        local ver
        ver=$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
        msg "Found $PYTHON_BIN (Python $ver)"
        # Check >= 3.9
        if "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then
            return 0
        fi
        warn "Python $ver is too old; need >= 3.9"
    fi

    msg "Python 3.9+ not found — attempting install"
    local os
    os=$(detect_os)
    case "$os" in
        ubuntu|debian|raspbian)
            sudo apt-get update
            sudo apt-get install -y python3 python3-venv python3-pip
            ;;
        fedora|centos|rhel)
            sudo dnf install -y python3 python3-pip
            ;;
        macos)
            if ! command -v brew >/dev/null 2>&1; then
                err "Homebrew not found. Install from https://brew.sh then re-run."
                exit 1
            fi
            brew install python
            ;;
        *)
            err "Unsupported OS '$os'. Please install Python 3.9+ manually and re-run."
            exit 1
            ;;
    esac
}

install_ironmesh() {
    msg "Creating venv at $VENV"
    mkdir -p "$PREFIX"
    "$PYTHON_BIN" -m venv "$VENV"
    # shellcheck disable=SC1091
    . "$VENV/bin/activate"
    pip install --quiet --upgrade pip wheel

    local extras=""
    if [ "${IRONMESH_NO_RNS:-0}" != "1" ]; then
        extras="[rns]"
    fi

    if [ -f "$SRC_DIR/pyproject.toml" ]; then
        msg "Installing IronMesh from $SRC_DIR (editable)"
        pip install --quiet -e "${SRC_DIR}${extras}"
    else
        msg "Installing IronMesh from PyPI"
        pip install --quiet "ironmesh${extras}"
    fi

    msg "IronMesh installed: $("$VENV/bin/ironmesh" --help 2>&1 | head -1 || echo 'ironmesh CLI available')"
}

setup_passphrase() {
    local env_file="$HOME/.ironmesh/environment"
    local pp_file="$HOME/.ironmesh/passphrase"
    mkdir -p "$HOME/.ironmesh"
    if [ -f "$pp_file" ]; then
        msg "Passphrase file exists at $pp_file — leaving untouched"
        return
    fi

    if [ -t 0 ]; then
        msg "Generating passphrase file at $pp_file (min 12 chars)"
        while true; do
            read -rsp "Enter a strong passphrase (>=12 chars): " pp1
            echo
            if [ "${#pp1}" -lt 12 ]; then
                warn "Too short; must be at least 12 characters."
                continue
            fi
            read -rsp "Confirm passphrase: " pp2
            echo
            if [ "$pp1" != "$pp2" ]; then
                warn "Passphrases don't match; try again."
                continue
            fi
            break
        done
        printf '%s' "$pp1" > "$pp_file"
        chmod 600 "$pp_file"
    else
        warn "Non-interactive install; skipping passphrase prompt."
        warn "Create $pp_file manually with a strong passphrase (>= 12 chars)."
    fi

    if [ ! -f "$env_file" ]; then
        cat > "$env_file" <<EOF
# IronMesh environment file — loaded by systemd unit
IRONMESH_PASSPHRASE_FILE=$pp_file
IRONMESH_NAME=$(hostname -s)
EOF
        chmod 600 "$env_file"
    fi
}

install_systemd() {
    if [ "${IRONMESH_NO_SYSTEMD:-0}" = "1" ]; then
        msg "Skipping systemd install (IRONMESH_NO_SYSTEMD=1)"
        return
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemctl not found; skipping service install"
        return
    fi

    local unit_src="$SRC_DIR/scripts/ironmesh.service"
    if [ ! -f "$unit_src" ]; then
        warn "systemd unit source not found at $unit_src; skipping"
        return
    fi

    local user_dir="$HOME/.config/systemd/user"
    mkdir -p "$user_dir"
    # Substitute the venv path into the ExecStart line
    sed "s|__IRONMESH_BIN__|$VENV/bin/ironmesh|g" "$unit_src" > "$user_dir/ironmesh.service"
    systemctl --user daemon-reload
    msg "Installed user unit at $user_dir/ironmesh.service"
    msg "Enable + start with:"
    msg "    systemctl --user enable --now ironmesh"
    msg "    loginctl enable-linger $USER    # start at boot without login"
}

main() {
    msg "IronMesh installer"
    install_python_if_missing
    install_ironmesh
    setup_passphrase
    install_systemd
    echo
    msg "Done. IronMesh CLI: $VENV/bin/ironmesh"
    msg "Add to PATH:       export PATH=\"$VENV/bin:\$PATH\""
    msg "See GETTING_STARTED.md for next steps."
}

main "$@"
