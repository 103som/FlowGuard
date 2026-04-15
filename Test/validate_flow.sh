#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?pcapng path}"
CLIENT_IP="${2:?client ip}"
CLIENT_PORT="${3:?client port}"
SERVER_IP="${4:?server ip}"
SERVER_PORT="${5:?server port}"
PROTO="${6:?proto: 6/tcp or 17/udp}"

if [[ "$PROTO" == "6" || "$PROTO" == "tcp" ]]; then
  L4="tcp"
elif [[ "$PROTO" == "17" || "$PROTO" == "udp" ]]; then
  L4="udp"
else
  echo "Unsupported proto: $PROTO"
  exit 1
fi

A="ip.src==$CLIENT_IP && $L4.srcport==$CLIENT_PORT && ip.dst==$SERVER_IP && $L4.dstport==$SERVER_PORT"
B="ip.src==$SERVER_IP && $L4.srcport==$SERVER_PORT && ip.dst==$CLIENT_IP && $L4.dstport==$CLIENT_PORT"

BI="(($A) || ($B))"
C2S="($A)"
S2C="($B)"

count_packets() {
  local filt="$1"
  tshark -r "$PCAP" -Y "$filt" -T fields -e frame.number 2>/dev/null | sed '/^$/d' | wc -l
}

sum_bytes() {
  local filt="$1"
  tshark -r "$PCAP" -Y "$filt" -T fields -e frame.len 2>/dev/null | awk '{s+=$1} END{print s+0}'
}

duration_ms() {
  local filt="$1"
  tshark -r "$PCAP" -Y "$filt" -T fields -e frame.time_epoch 2>/dev/null | \
    awk 'NR==1{f=$1} {l=$1} END{if (NR==0) print 0; else printf "%.6f\n", (l-f)*1000}'
}

echo "=== FLOW ==="
echo "PCAP        : $PCAP"
echo "CLIENT      : $CLIENT_IP:$CLIENT_PORT"
echo "SERVER      : $SERVER_IP:$SERVER_PORT"
echo "PROTO       : $L4"
echo

echo "=== BASIC ==="
echo "packets_total      : $(count_packets "$BI")"
echo "packets_c2s        : $(count_packets "$C2S")"
echo "packets_s2c        : $(count_packets "$S2C")"
echo "bytes_wire_total   : $(sum_bytes "$BI")"
echo "bytes_wire_c2s     : $(sum_bytes "$C2S")"
echo "bytes_wire_s2c     : $(sum_bytes "$S2C")"
echo "duration_ms        : $(duration_ms "$BI")"
echo

if [[ "$L4" == "tcp" ]]; then
  echo "=== TCP FLAGS ==="
  echo "tcp_syn_total      : $(count_packets "($BI) && tcp.flags.syn==1")"
  echo "tcp_syn_c2s        : $(count_packets "($C2S) && tcp.flags.syn==1 && tcp.flags.ack==0")"
  echo "tcp_synack_s2c     : $(count_packets "($S2C) && tcp.flags.syn==1 && tcp.flags.ack==1")"
  echo "tcp_ack_total      : $(count_packets "($BI) && tcp.flags.ack==1")"
  echo "tcp_fin_total      : $(count_packets "($BI) && tcp.flags.fin==1")"
  echo "tcp_rst_total      : $(count_packets "($BI) && tcp.flags.reset==1")"
  echo "tcp_psh_total      : $(count_packets "($BI) && tcp.flags.push==1")"
  echo
  echo "=== TLS ==="
  echo "client_hello_c2s   : $(count_packets "($C2S) && tls.handshake.type==1")"
fi
