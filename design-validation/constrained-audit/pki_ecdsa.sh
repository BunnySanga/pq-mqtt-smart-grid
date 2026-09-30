#!/bin/sh
# ECDSA P-256 PKI, the certificate type the design actually uses on the broker hop (BalaMP.md §3.2).
# Extra device certificates for the time experiments:
#   devlong  : notAfter 9999-12-31 (RFC 5280 §4.1.2.5 "no well-defined expiration")
#   devexp   : already expired (models a device that stayed offline past its certificate lifetime)
set -e
rm -rf /audit/pki; mkdir -p /audit/pki; cd /audit/pki
EC="-newkey ec -pkeyopt ec_paramgen_curve:P-256"
openssl req -x509 $EC -keyout ca.key -out ca.crt -days 3650 -nodes -subj "/CN=pqgrid-audit-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" 2>/dev/null
leaf() { # $1=file $2=CN $3=EKU $4=validity-args $5=SAN(optional)
  openssl req $EC -keyout $1.key -out $1.csr -nodes -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=$3" ${5:+-addext "subjectAltName=$5"} 2>/dev/null
  openssl x509 -req -in $1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $1.crt $4 -copy_extensions copy 2>/dev/null
}
leaf broker  broker     serverAuth "-days 825" "DNS:localhost,IP:127.0.0.1"
leaf meter1  meter-0001 clientAuth "-days 825"
leaf utility utility    clientAuth "-days 825"
leaf devlong meter-0002 clientAuth "-not_after 99991231235959Z"
leaf devexp  meter-0003 clientAuth "-not_before 20200101000000Z -not_after 20210101000000Z"
chmod 600 *.key; chown -R mosquitto:mosquitto /audit/pki 2>/dev/null || true
for c in broker meter1 devlong devexp; do
  printf '%-8s %5s B  ' $c "$(openssl x509 -in $c.crt -outform DER | wc -c)"
  openssl x509 -in $c.crt -noout -startdate -enddate | tr '\n' ' '; echo
done
