#!/bin/bash

trap "exit 1" SIGINT

CAS='/C=US/ST=State/L=City/O=Org/OU=Group/CN=CA Root/emailAddress=ca-root@domain.com'
CIS='/C=US/ST=State/L=City/O=Org/OU=Group/CN=CI_/emailAddress=ci_@domain.com'
CCS='/C=US/ST=State/L=City/O=Org/OU=Group/CN=Certy Cert/emailAddress=certycert@domain.com'

# NEVER DO THIS
L=1024 # super bad, do not use in production or on anything you care about
# NEVER DO THIS

O=( -days 3000 -sha256 )
K=( -nodes -new -newkey rsa:$L "${O[@]}" -config silly.cnf -extensions v3_ca )
J=( -nodes -new -newkey rsa:$L "${O[@]}" -config silly.cnf -extensions v3_intermediate_ca )
U=( -nodes -new -newkey rsa:$L "${O[@]}" -config silly.cnf )
S=( x509 -req -CA ca-root.crt -CAkey ca-root.key -CAcreateserial "${O[@]}" -extfile silly.cnf )
V=( verify -CAfile ca-root.crt -verbose )

rm -rf .pretend-certs
mkdir -vp .pretend-certs
cd .pretend-certs

cat > silly.cnf << EOF
[ blah]

[ req ]
distinguished_name = blah

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, digitalSignature, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign
EOF

echo; echo ------------=: create ca-root
openssl req -x509 "${K[@]}" -keyout ca-root.key -out ca-root.crt -subj "$CAS" || exit 1
echo

for i in 1 2; do
    echo; echo ------------=: create intermediate-$i
    ( set -x -e
      openssl req "${J[@]}" -keyout intermediate-$i.key -out intermediate-$i.csr -subj "${CIS//_/$i}"
      openssl "${S[@]}" -extensions v3_intermediate_ca -in intermediate-$i.csr -out intermediate-$i.crt
      openssl "${V[@]}" intermediate-$i.crt ) || exit 1
    echo

    echo; echo ------------=: create public-$i / private-$i
    I=( )
    for item in "${S[@]}";
    do case "$item" in
        ca-root.crt) I+=( intermediate-$i.crt ) ;;
        ca-root.key) I+=( intermediate-$i.key ) ;;
        *) I+=( "$item" ) ;;
    esac; done
    ( set -x -e
      openssl req "${U[@]}" -keyout private-$i.key -out temp-$i.csr -subj "$CCS"
      openssl "${I[@]}" -in temp-$i.csr -out public-$i.crt
      openssl "${V[@]}" -untrusted intermediate-$i.crt public-$i.crt ) || exit 1
    echo
done


echo; echo ------------=: final checks
rm -f *.csr
cat intermediate-*.crt > bundle.pem

for i in public-*.crt
do (set -x ; openssl "${V[@]}" -untrusted bundle.pem  $i)
done


echo
echo pretend keys generated and verified
echo do not use them for anything you care about
echo they are only for pretend
echo

