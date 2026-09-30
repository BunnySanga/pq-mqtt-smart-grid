#!/bin/sh
set -e
rm -rf /work/pki; mkdir -p /work/pki; cd /work/pki
openssl req -x509 -newkey mldsa65 -keyout ca.key -out ca.crt -days 30 -nodes -subj "/CN=pqgrid-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" 2>/dev/null
leaf() { # $1=file $2=CN $3=EKU $4=SAN(optional)
  openssl req -newkey mldsa65 -keyout $1.key -out $1.csr -nodes -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=$3" ${4:+-addext "subjectAltName=$4"} 2>/dev/null
  openssl x509 -req -in $1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $1.crt -days 30 -copy_extensions copy 2>/dev/null
}
leaf broker broker serverAuth "DNS:localhost,IP:127.0.0.1"
leaf meter1 meter-0001 clientAuth
leaf meter2 meter-0002 clientAuth
leaf utility utility clientAuth
chmod 600 *.key; chown -R mosquitto:mosquitto /work/pki 2>/dev/null || true
echo "PKI ok: $(ls *.crt | tr '\n' ' ')"
