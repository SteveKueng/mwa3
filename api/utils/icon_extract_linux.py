"""Linux-friendly best-effort icon extraction for Munki uploads.

Munki's native icon generation relies on macOS frameworks (Foundation/AppKit).
This module provides a limited alternative for Linux/container deployments:
- Extract installer archives (DMG/PKG) via `7z`.
- Find an embedded `.app` bundle.
- Convert the first reasonable icon candidate to PNG bytes.

This is intentionally best-effort: failures should never block uploads.
"""

from __future__ import annotations

import io
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None  # type: ignore


LOGGER = logging.getLogger("munkiwebadmin")


@dataclass(frozen=True)
class IconResult:
    png_bytes: bytes


def _run_7z_extract(archive_path: str, out_dir: str) -> bool:
    """Extract `archive_path` into `out_dir` using 7z.

    Returns True on success.
    """
    try:
        completed = subprocess.run(
            ["7z", "x", "-y", f"-o{out_dir}", archive_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=300,
        )
    except Exception:
        return False
    return completed.returncode == 0


def _iter_app_bundles(root_dir: str) -> list[Path]:
    apps: list[Path] = []
    root = Path(root_dir)
    if not root.exists():
        return apps

    for path in root.rglob("*.app"):
        if not path.is_dir():
            continue
        # Basic sanity check for a macOS app bundle
        if (path / "Contents" / "Info.plist").exists():
            apps.append(path)
    return apps


def _pick_icon_candidate(app_path: Path) -> Path | None:
    resources = app_path / "Contents" / "Resources"
    if not resources.exists():
        return None

    # Prefer icns (can contain multiple sizes)
    icns = sorted(resources.rglob("*.icns"))
    if icns:
        return icns[0]

    # Fall back to existing PNGs in Resources (some apps ship those)
    pngs = sorted(resources.rglob("*.png"))
    if pngs:
        # pick the largest file (rough proxy for best icon)
        return max(pngs, key=lambda p: p.stat().st_size if p.exists() else 0)

    return None


def _icns_to_png_bytes(icns_path: Path) -> bytes | None:
    if Image is None:
        return None

    try:
        img = Image.open(icns_path)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return None


def _png_file_to_bytes(png_path: Path) -> bytes | None:
    try:
        return png_path.read_bytes()
    except Exception:
        return None


def _second_stage_extract_images(root_dir: str) -> None:
    """Attempt a second-stage extraction for common embedded disk images."""
    root = Path(root_dir)
    if not root.exists():
        return

    # DMGs often unpack into one or more embedded images
    candidates = []
    for suffix in (".hfs", ".img", ".iso", ".udf"):
        candidates.extend(root.rglob(f"*{suffix}"))

    for candidate in candidates:
        # Extract each candidate into a sibling folder
        out_dir = str(candidate.parent / f"_extracted_{candidate.stem}")
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            continue
        _run_7z_extract(str(candidate), out_dir)


def generate_icon_png_bytes(installer_path: str) -> IconResult | None:
    """Best-effort icon extraction.

    Supports common Munki upload types: `.dmg` and `.pkg`.

    Returns IconResult(png_bytes) on success, otherwise None.
    """
    lower = installer_path.lower()
    if not (lower.endswith(".dmg") or lower.endswith(".pkg")):
        return None

    # If the file doesn't exist (shouldn't happen), bail.
    if not os.path.exists(installer_path):
        return None

    with tempfile.TemporaryDirectory(prefix="mwa_icon_") as tmp:
        if not _run_7z_extract(installer_path, tmp):
            return None

        # DMGs often contain embedded images; try one more extraction pass.
        if lower.endswith(".dmg"):
            _second_stage_extract_images(tmp)

        # PKGs sometimes contain an extracted Payload file; try extracting it.
        if lower.endswith(".pkg"):
            payloads = list(Path(tmp).rglob("Payload"))
            for payload in payloads[:3]:
                out_dir = str(payload.parent / "_payload")
                try:
                    os.makedirs(out_dir, exist_ok=True)
                except Exception:
                    continue
                _run_7z_extract(str(payload), out_dir)

        apps = _iter_app_bundles(tmp)
        if not apps:
            return None

        # Pick the first app (stable-ish), then choose an icon from it.
        icon_candidate = _pick_icon_candidate(apps[0])
        if not icon_candidate:
            return None

        if icon_candidate.suffix.lower() == ".icns":
            png_bytes = _icns_to_png_bytes(icon_candidate)
        else:
            png_bytes = _png_file_to_bytes(icon_candidate)

        if not png_bytes:
            return None

        return IconResult(png_bytes=png_bytes)
