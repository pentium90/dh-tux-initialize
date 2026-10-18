#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

if [ "$(uname -s)" != "Linux" ]; then
    echo "This build script requires Linux." >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ;;
    *) echo "This build script supports Linux x86_64 and ARM64 only." >&2; exit 1 ;;
esac

python_cmd=${PYTHON:-python}
"$python_cmd" -m PyInstaller \
    --clean \
    --noconfirm \
    --onefile \
    --console \
    --name dh-tux-initialize \
    --exclude-module dh_tux_initialize.cli \
    --exclude-module dh_tux_initialize.diagnostic_discovery \
    --exclude-module dh_tux_initialize.deep_discovery \
    --paths src \
    --workpath build/pyinstaller \
    --distpath dist \
    --specpath build/pyinstaller \
    scripts/pyinstaller_entrypoint.py
