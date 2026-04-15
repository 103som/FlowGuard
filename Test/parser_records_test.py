import pandas as pd

df = pd.read_csv("Tuesday.csv")

parts = []

x = df[(df["proto"] == 6) & (df["tls_client_hello_c2s"] == 0)]
if len(x) >= 4:
    parts.append(x.sample(4, random_state=42))

x = df[(df["proto"] == 6) & (df["tls_client_hello_c2s"] == 1)]
if len(x) >= 4:
    parts.append(x.sample(4, random_state=42))

x = df[df["proto"] == 17]
if len(x) >= 2:
    parts.append(x.sample(2, random_state=42))

x = df[(df["tcp_rst_total"] > 0) | (df["tcp_fin_total"] > 0)]
if len(x) >= 2:
    parts.append(x.sample(2, random_state=42))

parts.append(df.sort_values("packets_total", ascending=False).head(2))

sample = pd.concat(parts, ignore_index=True).drop_duplicates()
sample.to_csv("validation_sample.csv", index=False)

print(sample[[
    "client_ip","server_ip","client_port","server_port","proto",
    "packets_total","packets_c2s","packets_s2c",
    "bytes_wire_total","duration_ns",
    "tcp_syn_total","tcp_ack_total","tcp_fin_total","tcp_rst_total","tcp_psh_total",
    "tls_client_hello_c2s","ja4_legacy_version","ja4_cipher_suites_count",
    "ja4_extensions_count","ja4_has_sni","ja4_alpn"
]].to_string(index=False))
