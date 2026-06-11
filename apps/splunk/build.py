#!/usr/bin/env python3
"""
Splunk app paketleyici.

apps/splunk/ altindaki app dizinlerini Splunkbase/AppInspect uyumlu
.tar.gz (.spl esdegeri) paketlerine cevirir:

    python apps/splunk/build.py                 # iki app'i de paketle
    python apps/splunk/build.py --app sgb_usecases

Cikti: apps/splunk/dist/<app>-<version>.tar.gz
- Arsiv koku app dizin adidir (AppInspect sarti).
- local/, *.pyc, __pycache__, .DS_Store haric tutulur.
- Dosya modlari normalize edilir (dir 755, dosya 644).
"""
import argparse
import configparser
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
APPS = ["TA-sgb-threat-intel", "sgb_usecases"]
EXCLUDE_NAMES = {"__pycache__", ".DS_Store", "local", ".gitignore", "dist"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".tmp"}


def app_version(app_dir: Path) -> str:
    cp = configparser.ConfigParser(strict=False)
    cp.read(app_dir / "default" / "app.conf", encoding="utf-8")
    return cp.get("launcher", "version", fallback="0.0.0")


def _excluded(path: Path) -> bool:
    if path.name in EXCLUDE_NAMES or path.suffix in EXCLUDE_SUFFIXES:
        return True
    return any(part in EXCLUDE_NAMES for part in path.parts)


def _normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = 0o755 if info.isdir() else 0o644
    return info


def build(app_name: str) -> Path:
    app_dir = HERE / app_name
    if not app_dir.is_dir():
        raise SystemExit(f"app dizini yok: {app_dir}")
    dist = HERE / "dist"
    dist.mkdir(exist_ok=True)
    out = dist / f"{app_name}-{app_version(app_dir)}.tar.gz"
    with tarfile.open(out, "w:gz") as tar:
        for path in sorted(app_dir.rglob("*")):
            if _excluded(path.relative_to(app_dir)):
                continue
            arcname = f"{app_name}/{path.relative_to(app_dir).as_posix()}"
            tar.add(path, arcname=arcname, recursive=False, filter=_normalize)
    print(f"OK  {out}  ({out.stat().st_size / 1024:.0f} KB)")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", choices=APPS, help="tek app paketle (default: hepsi)")
    args = ap.parse_args()
    for name in [args.app] if args.app else APPS:
        build(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
