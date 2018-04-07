# Welcome to pam_p11

Pam_p11 is a plugable authentication module (pam) package for using crpytographic tokens such as smart cards and usb crypto tokens for authentication.

Pam_p11 uses [libp11](https://github.com/OpenSC/libp11/) to access any PKCS#11 module. It should be compatible with any implementation, but it is primarely developed using [OpenSC](https://github.com/OpenSC/OpenSC/).

Pam_p11 implements two authentication methods:

- verify a token using a known public key found in OpenSSH's `~/.ssh/authorized_keys`.
- verify a token using a known certificate found in `~/.eid/authorized_certificates`.

Pam_p11 is very simple, it has no config file, no options other than the PKCS#11 module file, does not know about certificate chains, certificate authorities, revocation lists or OCSP. Perfect for the small installation with no frills.

Pam_p11 was written by an international team and is licensed as Open Source software under the LGPL license.

[![Build Status](https://travis-ci.org/OpenSC/pam_p11.svg?branch=master)](https://travis-ci.org/OpenSC/pam_p11)

## Installing pam_p11

Installation is quite easy:

```
wget https://github.com/OpenSC/pam_p11/releases/download/pam_p11-0.1.6/pam_p11-0.1.6.tar.gz
tar xfvz pam_p11-0.1.6.tar.gz
cd pam_p11-0.1.6
./configure --prefix=/usr --libdir=/lib/
make
make install
```

Pam_p11 depends on pkg-config, openssl, libp11 and pam.  If you don't have pkg-config installed, please do so and try again.  If pkg-config is not found, please change your PATH environment setting.  If openssl is not installed, please do so. If openssl is not found, please change your PKG_CONFIG_PATH environment setting to include the directory with "openssl.pc" or "libp11.pc" file. Some linux distributions split openssl into a runtime package and a development package, you need to install both. Same might be true for pam and libp11.

## Using pam_p11

To use pam_p11 with some application like login, edit /etc/pam.d/login and replace

```
auth       required     pam_unix.so nullok
```

with

```
auth       required     pam_p11.so  /usr/lib/opensc-pkcs11.so
```

Replace `/usr/lib/opensc-pkcs11.so` with your PKCS#11 implementation.

Also while testing it is best to keep a door open, i.e. allow also login via passwords. To try pam_p11 first and then password put into your pam configuration:

```
auth       sufficient   pam_p11.so  /usr/lib/opensc-pkcs11.so
auth       required     pam_unix.so nullok
```

To allow changing and unblocking the PIN via pam_p11, replace

```
password   required     pam_unix.so use_authtok nullok sha512
```

with
```
password   optional     pam_p11.so  /usr/lib/opensc-pkcs11.so
password   required     pam_unix.so use_authtok nullok sha512
```

### User configuration via `~/.eid/authorized_certificates`

A user may create a `~/.eid/` directory and create a file `~/.eid/authorized_certificates` with the authorized certificate. You can do that via

```
mkdir -p ~/.eid
chmod 0755 ~/.eid
pkcs15-tool -r 45 >> ~/.eid/authorized_certificates
chmod 0644 ~/.eid/authorized_certificates
```

This example uses the "pkcs15-tool" command from opensc to read the default user certificate (id `45`) from the smart card.

It is very important that only the user of the file can write to it.  You can have any number of certificates in that file. The certificates need to be in "pem" format. "der" format is currently not supported.

### User configuration via `~/.ssh/authorized_keys`

A user may create a `~/.ssh/` directory and create a file `~/.ssh/authorized_keys` with the authorized public key. You can do that via

```
mkdir -p ~/.ssh
chmod 0755 ~/.ssh
ssh-keygen -D /usr/lib/opensc-pkcs11.so >> ~/.ssh/authorized_keys
chmod 0644 ~/.ssh/authorized_keys
```

This example uses the "ssh-keygen" command from openssh to read the default user public key (id 45) from the smart card in reader 0.  Note that this tool prints the public keys in two formats: ssh v1 and ssh v2 format. It is recommended to edit the file and delete one of those two lines. Also you might want to add a comment / identifier at the end of the line.

It is very important that only the user of the file can write to it.  You can have any number of public keys in that file.

Note it is currently not possible to convert existing ssh keys into pem format and store them on a smart card. (To be precise: OpenSC has no such functionality, not sure about other implementations.)

## Security Note

Both pam_p11 modules are plain, they simple compare public keys and request the cryptographic token to sign some random data and verifiy the signature with the public key. No CA chain checking is done, no CRL is looked at, and they don't know what OCSP is. This works fine for small installations, but if you want any of those features, please have a look at [Pam_pkcs11](https://github.com/OpenSC/pam_pkcs11) for a fully fledged pam module for smart card authentication.
