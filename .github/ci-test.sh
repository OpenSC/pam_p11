#!/bin/bash
set -e
SOPIN="12345678"
PIN="123456"

make

P11LIB=/usr/lib/softhsm/libsofthsm2.so

echo "directories.tokendir = .tokens/" > .softhsm2.conf
export SOFTHSM2_CONF=".softhsm2.conf"

echo ""
echo "Testing login using .ssh/authorized_keys"
echo "----------------------------------------"
mkdir -p $HOME/.ssh
for KEY in RSA:2048 EC:secp256r1 EC:secp384r1 EC:secp521r1; do
	rm -rf .tokens
	mkdir .tokens

	softhsm2-util --init-token --slot 0 --label "SC test" --so-pin="$SOPIN" --pin="$PIN"

	# ubuntu 20.04, ssh-keygen is unable to extract EC key if --id is not specified
	#
	# ssh-keygen -D /usr/lib/softhsm/libsofthsm2.so
	# xmalloc: zero size

	pkcs11-tool --module="$P11LIB" --keypairgen --key-type=$KEY --label "${KEY}" --login --pin=$PIN --id 01

	ssh-keygen -D $P11LIB >> $HOME/.ssh/authorized_keys
	echo $PIN | sudo -E src/test-login $P11LIB $(whoami)
done
rm $HOME/.ssh/authorized_keys

echo ""
echo "Testing login Using .eid/authorized_certificates"
echo "------------------------------------------------"
mkdir -p $HOME/.eid
for KEY in 2048 prime256v1 secp384r1 secp521r1; do

	if [ $[$KEY + 0 ] != 0 ]; then
		openssl genrsa -out user.key $KEY
		openssl rsa -in user.key -pubout -outform DER -out user.pub.der 2>/dev/null
		openssl rsa -in user.key -outform DER -out user.key.der 2>/dev/null
	else
		openssl ecparam -out user.key -name $KEY -genkey
		openssl ec -in user.key -pubout -outform DER -out user.pub.der 2>/dev/null
		openssl ec -in user.key -outform DER -out user.key.der 2>/dev/null
	fi
	openssl req -new -nodes -key user.key -outform pem -out user.csr -sha256 -subj "/C=EX/CN=example.com" >/dev/null
	openssl x509 -signkey user.key -in user.csr -req -days 365 -out user.crt 2>/dev/null
	cp user.crt $HOME/.eid/authorized_certificates

	echo "Using softhsm (key + public key)"
	rm -rf .tokens
	mkdir .tokens
	softhsm2-util --init-token --slot 0 --label "SC test" --so-pin="$SOPIN" --pin="$PIN"
	pkcs11-tool --module="$P11LIB" --write-object user.key.der --type privkey --label "${KEY}" --login --pin=$PIN --id 01 2>/dev/null
	pkcs11-tool --module="$P11LIB" --write-object user.pub.der --type pubkey --label "${KEY}" --login --pin=$PIN --id 01 >/dev/null 2>/dev/null
	echo $PIN |src/test-login $P11LIB $(whoami)

done
rm $HOME/.eid/authorized_certificates

rm user.key user.pub.der user.key.der user.csr user.crt
rmdir $HOME/.eid/

rm -rf .tokens
rm .softhsm2.conf
