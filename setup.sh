#!/bin/bash
#
# Set up our nymserver directory and encryption keys.

NYMDIR=$HOME/Nym
GPG=$(which gpg)

KEYDIR=$NYMDIR/pgp

usage () {
    cat <<EOF
setup.sh [-n|--nymdir NYMDIR] [-g|--gpg /path/to/gpg] passphrase hostname

    Begins setting up the Nymserver in NYMDIR (defaults to $NYMDIR).
    The passphrase is your keyserver's default passphrase, so make sure
    to remember it.
    Make sure to specify the hostname, which is the hostname your
    Nymserver will be using.
EOF
    exit 0
}

# Read our command-line options.
while test $# != 0
do
    case "$!" in
        -n|--nymdir)
            shift
            NYMDIR="$1"
            shift
            ;;
        -g|--gpg)
            shift
            GPG="$1"
            shift
            ;;
        -*)
            usage
            ;;
        *)
            break
            ;;
        esac
done
PASSPHRASE="$1"
NYMHOST="$2"

if test "x$NYMHOST" == "x"
then
    usage
fi

# Create our directories and go there.
mkdir -p $NYMDIR
mkdir -p $KEYDIR
chmod 700 $KEYDIR
sed -e "s|__PASSPHRASE__|${PASSPHRASE}|" \
    -e "s|__NYMHOST__|${NYMHOST}|" < gpg-gen-key.conf.in > gpg-gen-key.conf

if [ ! -d $NYMDIR ]
then
    echo "Unable to create Nymserver home directory in $NYMDIR"
    exit 1
fi

# Install our nymserver script and README file.
echo "Installing Nymserver in $NYMDIR ..."
install -m750 nymserver.pl $NYMDIR
install -m640 README $NYMDIR
install -m400 gpg-gen-key.conf $NYMDIR

cd $NYMDIR

# Make backups of old files, if they exist.
echo "Backing up old GnuPG files in $KEYDIR ..."
for file in secring.pgp pubring.pgp
do
    if [ -f "$KEYDIR/$file" ]; then
        mv "$KEYDIR/$file" "$KEYDIR/$file.bak"
    fi
done

echo "Generating GnuPG keys for Nymserver ..."
$GPG --homedir "$KEYDIR" --s2k-cipher-algo BLOWFISH --cipher-algo TWOFISH \
     --no-secmem-warning --no-default-keyring         \
     --keyring "$KEYDIR/pubring.pgp"                  \
     --secret-keyring "$KEYDIR/secring.pgp"           \
     --batch --gen-key gpg-gen-key.conf

cp -v "$KEYDIR/pubring.pgp" "$NYMDIR/ring-proto.pgp"
$GPG --homedir "$KEYDIR" --s2k-cipher-algo BLOWFISH --cipher-algo TWOFISH \
     --no-secmem-warning --no-default-keyring         \
     --keyring "$KEYDIR/pubring.pgp"                  \
     --armor --export > "$KEYDIR/pubring.asc"

# TODO:
# * Add the send@$NYMHOST identity to the key.  Not sure how to do this in batch mode.
# * Use sed to set some configuration items in nymserver.pl.
# * Configure Mixmaster correctly.
# * Maybe send a test email?

# Now create our other directories.
mkdir -p $NYMDIR/users
mkdir -p $NYMDIR/queue
mkdir -p $NYMDIR/.gnupg
chmod 700 $NYMDIR/.gnupg
touch $NYMDIR/.gnupg/noring.gpg
chmod 600 $NYMDIR/.gnupg/noring.gpg

