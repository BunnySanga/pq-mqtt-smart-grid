#!/bin/sh
cd /work
for ALG in mldsa65 mldsa44 ecp256; do
  D=/tmp/pki_$ALG; rm -rf $D; mkdir -p $D; cd $D
  if [ $ALG = ecp256 ]; then NK="-newkey ec -pkeyopt ec_paramgen_curve:P-256"; else NK="-newkey $ALG"; fi
  openssl req -x509 $NK -keyout ca.key -out ca.crt -days 30 -nodes -subj "/CN=ca" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
  for L in "broker serverAuth DNS:localhost" "meter1 clientAuth"; do set -- $L
    openssl req $NK -keyout $1.key -out $1.csr -nodes -subj "/CN=$1" -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=$2" ${3:+-addext "subjectAltName=$3"} 2>/dev/null
    openssl x509 -req -in $1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $1.crt -days 30 -copy_extensions copy 2>/dev/null
  done
  DER=$(openssl x509 -in meter1.crt -outform DER | wc -c)
  cat > m.conf <<C
allow_anonymous false
user root
log_dest stderr
set_tcp_nodelay true
listener 8890
cafile $D/ca.crt
certfile $D/broker.crt
keyfile $D/broker.key
tls_version tlsv1.3
require_certificate true
use_identity_as_username true
C
  mosquitto -c m.conf 2>m.log & MP=$!; sleep 0.8; grep -iE "error|unable" m.log | head -3
  F=$( (sleep 0.5; echo Q) | openssl s_client -connect localhost:8890 -CAfile ca.crt -cert meter1.crt -key meter1.key -sess_out s.pem 2>&1 | grep "handshake has read" | sed -E 's/.*read ([0-9]+) bytes and written ([0-9]+).*/\1 \2/')
  R=$( (sleep 0.5; echo Q) | openssl s_client -connect localhost:8890 -CAfile ca.crt -cert meter1.crt -key meter1.key -sess_in s.pem 2>&1 | grep "handshake has read" | sed -E 's/.*read ([0-9]+) bytes and written ([0-9]+).*/\1 \2/')
  set -- $F; FT=$(( $1 + $2 )); set -- $R; RT=$(( $1 + $2 ))
  printf "%-8s leaf cert DER %5d B | full handshake %6d B total | resumed %6d B total\n" $ALG $DER $FT $RT
  kill $MP; wait $MP 2>/dev/null; cd /work
done
