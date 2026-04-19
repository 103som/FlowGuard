#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
from pathlib import Path

# ==== НАСТРОЙКИ ====

PROJECT_ROOT = Path(__file__).resolve().parents[2]

VAL_CSV = PROJECT_ROOT / "data/processed/experiment2_source_aware/experiment2_val.csv"
OUTDIR = PROJECT_ROOT / "data/demo_showcase/raw"
MANIFEST_PATH = PROJECT_ROOT / "data/demo_showcase/manifest.json"

RAW_ROOTS = {
    "benign_tls": PROJECT_ROOT / "data/raw/mta/benign_tls",
    "tls_malware_ja4": PROJECT_ROOT / "data/raw/mta/tls_ja4",
    "flow_ja4_anomaly_TLS": PROJECT_ROOT / "data/raw/mta/flow_ja4",
}

# Именно те файлы, которые ты выбрал по VAL
SELECTION = [
    {
        "slot": "01_benign_tls",
        "group_name": "benign_tls",
        "source_file": "BenignDoH_NonDoH-Chrome-Google/Google/dump_00001_20200113100617",
        "offset_sec": 0,
        "kind": "benign_tls",
        "description": "Benign TLS фон из VAL",
    },
    {
        "slot": "02_icedid",
        "group_name": "tls_malware_ja4",
        "source_file": "2023-09-28-IcedID-infection-with-Keyhole-VNC-and-Cobalt-Strike",
        "offset_sec": 600,
        "kind": "malicious_tls",
        "description": "Крупный malicious TLS пример из VAL",
    },
    {
        "slot": "03_asyncrat_xworm",
        "group_name": "tls_malware_ja4",
        "source_file": "2024-03-14-AsyncRAT-and-XWorm-infection-traffic",
        "offset_sec": 1200,
        "kind": "malicious_tls",
        "description": "Второй malicious TLS пример из VAL",
    },
    {
        "slot": "04_tunnel_g3",
        "group_name": "flow_ja4_anomaly_TLS",
        "source_file": "MaliciousDoH-iodine-pcap-001_600/iodine_null-32-tunnel_1111_doh1_2020-03-22T12:06:12.717032",
        "offset_sec": 1800,
        "kind": "tunnel_tls",
        "description": "Tunnel / covert channel пример из G3",
    },
]

ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap"}


def normalize(s: str) -> str:
    return str(s).replace("\\", "/").strip("/")


def build_candidate_paths(root: Path, source_file: str) -> list[Path]:
    rel = Path(source_file)
    cands = []

    # exact relative path with / without suffix
    cands.append(root / rel)
    for suf in ALLOWED_SUFFIXES:
        cands.append(root / f"{source_file}{suf}")

    # exact basename with suffix
    base = rel.name
    for suf in ALLOWED_SUFFIXES:
        cands.append(root / f"{base}{suf}")

    return cands


def score_path(root: Path, path: Path, source_file: str) -> int:
    """
    Чем выше score, тем лучше совпадение.
    """
    rel = normalize(path.relative_to(root).with_suffix("").as_posix())
    src = normalize(source_file)
    base = normalize(Path(source_file).name)

    if rel == src:
        return 100
    if rel.endswith(src):
        return 90
    if Path(rel).name == base:
        return 80
    if base in rel:
        return 50
    return 0


def find_capture(root: Path, source_file: str) -> Path | None:
    # 1. быстрые точные проверки
    for cand in build_candidate_paths(root, source_file):
        if cand.exists() and cand.is_file():
            if cand.suffix.lower() in ALLOWED_SUFFIXES or cand.suffix == "":
                return cand

    # 2. рекурсивный поиск
    all_files = []
    for suf in ALLOWED_SUFFIXES:
        all_files.extend(root.rglob(f"*{suf}"))

    scored = []
    for f in all_files:
        sc = score_path(root, f, source_file)
        if sc > 0:
            scored.append((sc, len(str(f)), f))

    if not scored:
        return None

    scored.sort(key=lambda x: (-x[0], x[1]))
    return scored[0][2]


def main() -> None:
    OUTDIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)

    manifest = {
        "project_root": str(PROJECT_ROOT),
        "output_dir": str(OUTDIR),
        "items": [],
    }

    copied = []
    missing = []

    for item in SELECTION:
        root = RAW_ROOTS[item["group_name"]]
        src = find_capture(root, item["source_file"])

        if src is None:
            missing.append(
                {
                    "slot": item["slot"],
                    "group_name": item["group_name"],
                    "source_file": item["source_file"],
                    "searched_root": str(root),
                }
            )
            continue

        # копируем с дружелюбным именем
        dst = OUTDIR / f"{item['slot']}{src.suffix.lower()}"
        shutil.copy2(src, dst)

        copied_item = dict(item)
        copied_item["src_path"] = str(src)
        copied_item["dst_path"] = str(dst)
        copied_item["suffix"] = src.suffix.lower()

        copied.append(copied_item)
        manifest["items"].append(copied_item)

    with MANIFEST_PATH.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print("\n[OK] copied files:")
    for x in copied:
        print(f"  {x['slot']}: {x['dst_path']}")

    if missing:
        print("\n[WARN] missing files:")
        for x in missing:
            print(f"  {x['slot']} | {x['group_name']} | {x['source_file']}")

    print(f"\n[OK] wrote manifest: {MANIFEST_PATH}")


if __name__ == "__main__":
    main()
