#!/bin/bash
set -e
SOPIN="12345678"
PIN="123456"

make

P11LIB=/usr/lib/softhsm/libsofthsm2.so

echo "directories.tokendir = .tokens/" > .softhsm2.conf
export SOFTHSM2_CONF=".softhsm2.conf"

mkdir -p $HOME/.ssh


for KEY in RSA:2048 EC:secp256r1 EC:secp384r1 EC:secp521r1; do
	rm -rf .tokens
	mkdir .tokens

	softhsm2-util --init-token --slot 0 --label "SC test" --so-pin="$SOPIN" --pin="$PIN"

	# ubuntu 20.04, ssh-keygen is unable to extract EC key if --id is not specified
	#
	# ssh-keygen -D /usr/lib/softhsm/libsofthsm2.so
	# xmalloc: zero size

	pkcs11-tool --module="$P11LIB" --keypairgen --key-type=$KEY --login --pin=$PIN --id 01

	ssh-keygen -D $P11LIB >> $HOME/.ssh/authorized_keys
	echo $PIN | sudo -E src/test-login $P11LIB $(whoami)
done

rm -rf .tokens
rm .softhsm2.conf
