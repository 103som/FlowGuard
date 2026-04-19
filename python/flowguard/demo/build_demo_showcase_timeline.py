#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MANIFEST_PATH = PROJECT_ROOT / "data/demo_showcase/manifest.json"
SHIFTED_DIR = PROJECT_ROOT / "data/demo_showcase/shifted"
OUT_PCAP = PROJECT_ROOT / "data/demo_showcase/demo_showcase_timeline_mix.pcap"


def run(cmd: list[str]) -> None:
    print("[RUN]", " ".join(cmd))
    subprocess.run(cmd, check=True)


def main() -> None:
    if shutil.which("editcap") is None:
        raise RuntimeError("editcap not found in PATH. Install tshark/wireshark-cli.")
    if shutil.which("mergecap") is None:
        raise RuntimeError("mergecap not found in PATH. Install tshark/wireshark-cli.")

    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    SHIFTED_DIR.mkdir(parents=True, exist_ok=True)

    shifted_files = []

    for item in manifest["items"]:
        src = Path(item["dst_path"])
        dst = SHIFTED_DIR / f"{item['slot']}_shifted.pcap"
        offset = float(item["offset_sec"])

        # Сдвиг времени и конвертация в pcap
        run([
            "editcap",
            "-F", "pcap",
            "-t", str(offset),
            str(src),
            str(dst),
        ])
        shifted_files.append(dst)

    # Склеиваем в один файл
    cmd = ["mergecap", "-F", "pcap", "-w", str(OUT_PCAP)]
    cmd.extend(str(x) for x in shifted_files)
    run(cmd)

    print(f"\n[OK] wrote merged showcase pcap: {OUT_PCAP}")


if __name__ == "__main__":
    main()
