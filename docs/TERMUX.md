# Running IronMesh on Android (Termux)

IronMesh runs on Android phones via [Termux](https://termux.dev/) — a
Linux environment that installs from F-Droid (or the Play Store with
some caveats).  This gives you a full IronMesh node in your pocket with
no app-store friction.

> **Recommended path for most mobile users:** use the
> [LXMF gateway](https://github.com/WizTheAgent/IronMesh/blob/main/examples/lxmf_gateway.py) with
> [Sideband](https://unsigned.io/sideband) (native iOS/Android Reticulum
> messenger). Termux is for operators who want CLI access.

## Install Termux

1. Install **F-Droid** from <https://f-droid.org/>
2. Install **Termux** from F-Droid (the Play Store version is deprecated)
3. Open Termux

## Install IronMesh

```bash
pkg update
pkg install python git
pkg install build-essential   # for pynacl native extensions
git clone https://github.com/WizTheAgent/ironmesh
cd ironmesh
pip install -e .
```

If you want LoRa support (requires USB-OTG adapter + RNode hardware):

```bash
pkg install termux-api
pip install -e ".[rns]"
```

## First run

```bash
# Create a passphrase file
mkdir -p ~/.ironmesh
echo 'a-strong-passphrase-at-least-12-chars' > ~/.ironmesh/passphrase
chmod 600 ~/.ironmesh/passphrase

# Generate keys
ironmesh keys generate --path ~/.ironmesh/keys.json

# Start the bridge
IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase \
    ironmesh run --name my-phone --port 8765 \
    --gui --allow-plaintext-ws --open-discovery
```

Dashboard: `http://localhost:8766/` (open in your phone's browser).

## Keep it running in the background

```bash
# Install termux-services
pkg install termux-services
sv-enable ironmesh
```

Or just use `nohup` / `tmux`.

## Battery considerations

- Reticulum / LoRa radios draw continuous current; an RNode on USB-OTG
  will drain your phone battery quickly
- For "always on" use, run IronMesh on a dedicated device (Pi, old
  phone on a charger) and use the LXMF gateway to reach your main phone

## Limitations

- mDNS on Android is flaky in some ROMs; use explicit `--rns-connect`
  destination hashes for reliable Reticulum discovery
- No native notifications — pair with an LXMF gateway + Sideband for
  push-to-phone behavior
- Termux sandbox limits some syscalls; the systemd-level hardening in
  `scripts/ironmesh.service` does not apply
