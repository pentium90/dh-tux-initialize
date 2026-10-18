"""PyInstaller bootstrap for the public release command line."""

from dh_tux_initialize.release_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
