#!/bin/bash

# CI script to build for "ubuntu", "coverity", "macos"

set -ex -o xtrace

DEPS="gettext automake"

case "$1" in
    ubuntu|coverity)
        DEPS="$DEPS autopoint libp11-dev libssl-dev libpam0g-dev"
        ;;
    macos)
        DEPS="$DEPS libp11 openssl"
        ;;
esac

case "$1" in
    ubuntu|coverity|mingw-32|mingw-64)
        sudo apt-get install -y $DEPS
        ;;
    macos)
        brew install $DEPS
        export LDFLAGS="-L$(brew --prefix gettext)/lib -lintl"
        export OPENSSL_CFLAGS="-I$(brew --prefix openssl)/include"
        export OPENSSL_LIBS="-L$(brew --prefix openssl)/lib -lcrypto"
        # TODO https://github.com/OpenSC/pam_p11/pull/22
        export CPPFLAGS="-DOPENSSL_SUPPRESS_DEPRECATED"
        ;;
esac

autoreconf -vis
./configure

case "$1" in
    ubuntu|macos)
        make distcheck
        ;;
esac
