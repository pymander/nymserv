#!/bin/bash
#
# Set up our nymserver directory and encryption keys.

NYMDIR=$HOME/Nym
GPG=/usr/bin/gpg

KEYDIR=$NYMDIR/pgp

mkdir -p $KEYDIR

for file in secring.pgp pubring.pgp
do
    if [ -f "$KEYDIR/$file" ]; then
        mv "$KEYDIR/$file" "$KEYDIR/$file.bak"
    fi
done

echo "Generating GnuPG keys for Nymserver..."
$GPG --homedir "$KEYDIR" --s2k-cipher-algo BLOWFISH --cipher-algo TWOFISH \
     --no-secmem-warning --no-default-keyring         \
     --keyring "$KEYDIR/pubring.pgp"                  \
     --secret-keyring "$KEYDIR/secring.pgp"           \
     --gen-key

cp -v "$KEYDIR/pubring.pgp" "$NYMDIR/ring-proto.pgp"
$GPG --homedir "$KEYDIR" --s2k-cipher-algo BLOWFISH --cipher-algo TWOFISH \
     --no-secmem-warning --no-default-keyring         \
     --keyring "$KEYDIR/pubring.pgp"                  \
     --armor --export > "$KEYDIR/pubring.asc"

