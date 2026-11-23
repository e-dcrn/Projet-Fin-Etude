#!/usr/bin/env bash
# Produit capture.pcap : un flux classique puis un flux furtif (port 2121 sur lo).
set -e
cd "$(dirname "$0")"
PY=../venv/bin/python   # venv avec pyftpdlib ; sinon: python3 avec pyftpdlib installé
"$PY" server.py >server.log 2>&1 & SRV=$!
sleep 1.5
# Capture : dumpcap si tu as les droits, sinon via un conteneur (comme le lab) :
CID=$(docker run -d --net=host --cap-add=NET_RAW -v "$PWD:/cap" idslab/toolbox:latest \
      tcpdump -i lo -f "tcp port 2121" -w /cap/capture.pcap -U)
sleep 1.2
echo "[*] classique"; "$PY" classic.py
sleep 1.5
echo "[*] furtif";    "$PY" stealth.py
sleep 1.2
docker kill --signal=INT "$CID" >/dev/null; docker rm -f "$CID" >/dev/null
kill $SRV 2>/dev/null || true
docker run --rm -v "$PWD:/cap" alpine:3.20 chown "$(id -u):$(id -g)" /cap/capture.pcap
echo "[*] OK -> capture.pcap  (isoler un flux : tshark -r capture.pcap -Y 'tcp.stream==0' -w flux.pcap)"
