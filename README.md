# DH-Tux-Initialize

Native Linux utility for discovering and initializing compatible Dahua IP
cameras and assigning their initial IPv4 configuration.

## Why this project exists

With Dahua ConfigTool running under Wine, I could find cameras that were already
initialized, but not an uninitialized camera. During that attempt, Wine reported
an unimplemented `WSAJoinLeaf` call.

Separately, [Wine MR 11819](https://gitlab.winehq.org/wine/wine/-/merge_requests/11819)
implements `WSAJoinLeaf`. Its author says the change fixes Dahua ConfigTool and
notes that ConfigTool uses Winsock 2 multicast when configuring or initializing
Dahua cameras. The Wine merge request does not describe the uninitialized
camera discovery observation above.

## Features

- Discover Dahua devices on the local network and identify uninitialized ones
- Initialize the admin account
- Configure DHCP or a static IPv4 address, subnet mask, and gateway
- Find the device again by MAC address and show the result

## Usage

After building from source:

```bash
chmod +x dh-tux-initialize
./dh-tux-initialize
```

Optional:

```bash
./dh-tux-initialize --help
./dh-tux-initialize --version
```

## Build from source

```bash
git clone https://github.com/pentium90/dh-tux-initialize.git
cd dh-tux-initialize

python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[build]'
./scripts/build-linux.sh
```

The binary is created at `dist/dh-tux-initialize`:

```bash
./dist/dh-tux-initialize
```

For fish, activate the environment with `source .venv/bin/activate.fish`.
PyInstaller builds are architecture-specific: building on x86-64 produces an
x86-64 binary; building on ARM64/aarch64 produces an ARM64 binary.

## Source installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
dh-tux-initialize
```

## Scope and limitations

This utility is for initial setup on a local network. It is not a full camera
configuration or web UI replacement; existing camera configuration remains
available through the camera's web interface. Access to the local LAN and its
multicast traffic is required.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](src/dh_tux_initialize/THIRD_PARTY_NOTICES.md).
