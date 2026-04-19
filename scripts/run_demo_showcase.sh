#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[1/3] Build named demo PCAP files"
python build_demo_showcase_pcaps.py

echo
echo "[2/3] Build merged timeline showcase PCAP"
python build_demo_showcase_timeline.py

echo
echo "[3/3] Done"
echo "Raw demo files:      ../../data/demo_showcase/raw/"
echo "Shifted demo files:  ../../data/demo_showcase/shifted/"
echo "Merged showcase:     ../../data/demo_showcase/demo_showcase_timeline_mix.pcap"
echo "Manifest:            ../../data/demo_showcase/manifest.json"
