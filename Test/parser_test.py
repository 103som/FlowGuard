import pandas as pd
import numpy as np

df = pd.read_csv("Tuesday.csv")

print("bad packets sum:", (df["packets_total"] != df["packets_c2s"] + df["packets_s2c"]).sum())
print("bad wire bytes sum:", (df["bytes_wire_total"] != df["bytes_wire_c2s"] + df["bytes_wire_s2c"]).sum())
print("bad cap bytes sum:", (df["bytes_cap_total"] != df["bytes_cap_c2s"] + df["bytes_cap_s2c"]).sum())
print("negative duration:", (df["duration_ns"] < 0).sum())

calc_avg = df["bytes_wire_total"] / df["packets_total"].replace(0, np.nan)
print("avg_wirelen mismatch > 1e-3:", ((df["avg_wirelen_total"] - calc_avg).abs() > 1e-3).sum())

placeholder = {"", "-", "none", "nan"}

legacy = df["ja4_legacy_version"].astype(str).str.strip().str.lower()
alpn = df["ja4_alpn"].astype(str).str.strip().str.lower()

bad_ja4 = (
    (df["tls_client_hello_c2s"] == 0) &
    (
        ~legacy.isin(placeholder) |
        ~alpn.isin(placeholder) |
        (pd.to_numeric(df["ja4_cipher_suites_count"], errors="coerce").fillna(0) > 0) |
        (pd.to_numeric(df["ja4_extensions_count"], errors="coerce").fillna(0) > 0) |
        (pd.to_numeric(df["ja4_has_sni"], errors="coerce").fillna(0) > 0)
    )
)

print("real JA4 fields without ClientHello:", bad_ja4.sum())
