from pathlib import Path
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
DATA_DIR = PROJECT_ROOT / "data"

base = DATA_DIR / "raw" / "cicids2017" / "labels" / "Friday"

parts = [
    base / "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet",
    base / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet",
    base / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet",
]

for p in parts:
    print(f"{p} exists = {p.exists()}")

df = pd.concat([pd.read_parquet(p) for p in parts], ignore_index=True)

df["Label"] = df["Label"].astype("string").str.strip()
df["Label"] = df["Label"].replace({
    "": pd.NA,
    "nan": pd.NA,
    "NaN": pd.NA,
    "None": pd.NA,
    "null": pd.NA,
    "<NA>": pd.NA,
})

print("rows before:", len(df))
print("missing Label before drop:", int(df["Label"].isna().sum()))

df = df[df["Label"].notna()].copy()

print("rows after:", len(df))
print("missing Label after drop:", int(df["Label"].isna().sum()))

out = base / "Friday-WorkingHours.pcap_ISCX.csv.parquet"
df.to_parquet(out, index=False)

print(f"[OK] wrote: {out}")
print(f"[OK] rows: {len(df)}")
