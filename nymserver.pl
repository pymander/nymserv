#!/usr/local/bin/perl -Tw
# $Revision: 1.1.1.1 $

#
# nymserv email pseudonym server
# email/finger <source@nym.alias.net> for installation instructions
# email/finger <licence@nym.alias.net> for a copy of the license
# 
# Copyright 1996-1998 David Mazieres
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

require 5.003;
use strict;

use POSIX qw(:errno_h :fcntl_h);
use DB_File;
use Socket;

require "sys/syscall.ph";

sub LOCK_SH () {0x01;}
sub LOCK_EX () {0x02;}
sub LOCK_NB () {0x04;}
sub LOCK_UN () {0x08;}

# Configuration:

my $HOMEDIR = '/usr/nym';
my $HOSTNAME = 'nym.alias.net';

my $SENDMAIL = '/usr/lib/sendmail';
my $QMAIL_CODES = 0; # Use qmail rather than sendmail exit codes
my $REMAIL = '/usr/remail/remailer';
my $PGP = '/usr/local/bin/pgp';
my $MD5 = '/usr/local/bin/md5sum'; # md5sum from GNU textutils

# When things get bad:
my $CONFIRM = 0;    # Require confirmation of reply-blocks
my $NOCREATE = 0;   # Don't allow creation of new nyms
my $QUOTEREQ = 1;   # Quote autoresponder requests

my $WARNAFTER = 90;
my $DELETEAFTER = 120;

# Stuff you probably don't need to change:
my $PGPPATH = $HOMEDIR . "/pgp";
my $PASSPHRASEFILE = $PGPPATH . "/passphrase";
my $RINGPROTO = "$HOMEDIR/ring-proto.pgp"; # Pubring with just our pub key
my $REPLAY = "$HOMEDIR/replay.db";   # Replay cache
my $CCC = "$HOMEDIR/confirm.db";     # Confirmation cookie cache
my $NDIR = $HOMEDIR . '/users';
my $QDIR = $HOMEDIR . '/queue';
my $QNAM = "q.$$";
my $QPREF = $QDIR . "/" . $QNAM;

my $PGPLOCK = "$QDIR/pgplock";      # Lock for unique access to randseed.bin

my $MAXLINES = 1024;
my $MSGPERDAY = 512;
my $MSGSZUNIT = 32768;
my $MSGSIZE = 10240;
my $SIGDAYS = 7; # Number of days a digital signature is good for

# Flags in user ".dat" file:
my $FL_ENCRECV = 0x1;
my $FL_SIGSEND = 0x2;
my $FL_ACKSEND = 0x100;
my $FL_DISABLED = 0x200;
my $FL_FIXEDSZ = 0x400;
my $FL_FINGERKEY = 0x800;
my $FL_NOBCC = 0x1000;
my $FL_NOLIMIT = 0x10000;
my $DEFFLAGS = 0xfd;

my @RSVD_NAMES = ("config", "send", "list", "root",
		  "nobody", "used", "confirm", "postmaster");

undef %ENV;
$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';
$ENV{'SHELL'} = '/bin/sh';
$ENV{'IFS'} = ' \t\r';
$ENV{'PGPPATH'} = $PGPPATH;

$SIG{'TERM'} = \&handler;

my $PASSPHRASE;

my $msgmd5;             # MD5 hash of message signature.
my $rmsgid;             # Unique message identifier for received messaged
my $pgppid;             # Process ID of child PGP process

my $lockuser;           # User whose files are locked
my $lockcount = 0;      # Number of times locked

sub fsync (\*) {
    my ($f) = @_;
    select ((select ($f), $|=1)[0]);
    syscall (&SYS_fsync, fileno ($f));
    return 1;
}
sub sync ($) {
    my ($path) = @_;
    local (*F);
    open (F, "<+$path") || return undef;
    fsync (*F);
    close (F);
    return 1;
}

sub wipefile (@) {
    local (*F);
    my ($file, $nblocks, $i);
    my $zeroes = pack "x8192";

    my $sigsave = $SIG{'TERM'};
    $SIG{'TERM'} = 'IGNORE';

    foreach $file (@_) {
	if (open F, "<+$file") {
	    if ($nblocks = (stat F)[7]) {
		$nblocks = ($nblocks + 0x1fff) >> 13;
		for ($i = 0; $i < $nblocks; $i++) {
		    print F $zeroes;
		}
	    }
	    fsync (*F);
	    close F;
	    truncate ("$file", 0);
	}
	unlink $file;
    }

    $SIG{'TERM'} = $sigsave;
}

sub saferename ($$) {
    my ($old, $new) = @_;
    my $tf = "$QPREF.w";
    wipefile ($tf);
    sync ($old);
    my $linked = link $new, $tf;
    my $ret = rename ($old, $new);
    if ($linked) {
	if ($ret) {
	    wipefile ($tf);
	}
	else {
	    unlink ($tf);
	}
    }
    return $ret;
}

sub copyfile (**) {
    my ($in, $out) = @_;
    my ($buf, $len) = ("");

    for (;;) {
	$len = read $in, $buf, 16384;
	($len <= 0) && return $len;
	((print {$out} $buf) < 0) && return -1;
    }
}

sub catfile {
    local (*F);
    my $ret = "";
    if (open F, "<" . $_[0]) {
        while (<F>) {$ret .= $_;}
        close (F);
    }
    else {
	die "$_[0]: $!";
    }
    $ret;
}

my $rndbuf = "";
sub randomval () {
    if (length ($rndbuf) < 4) {
	unlink ("$QPREF.rnd");
	&runpgp ("+makerandom=20 $QPREF.rnd");
	$rndbuf = &catfile ("$QPREF.rnd");
	unlink ("$QPREF.rnd");
    }
    my $val = vec ($rndbuf, 0, 32);
    $rndbuf = substr ($rndbuf, 4);
    $val;
}
sub randomstr () {
    &armor3bytes (&randomval);
}
sub randomfloat {
    my $val = &randomval & 0xffff;
    $val /= 65536.0;
    $val;
}

sub flock_db (\%$) {
    my ($href, $flags) = @_;
    local (*DB_FH);
    my $db = tied %$href;

    $db || fatal (70, "Couldn't get DB object.\n");
    $db->sync;
    open (DB_FH, "+<&" . $db->fd) || die "dup: $!";
    flock (DB_FH, $flags) || fatal (70, "Couldn't flock database: $!.\n");
}
sub tie_lock (\%$;$) {
    my ($href, $path, $flags) = @_;
    my $db;
    local (*DB_FH);

    tie (%$href, "DB_File", "$path", O_CREAT|O_RDWR, 0660, $DB_HASH)
	|| fatal (75, "Couldn't open database: $!.\n");
    $flags = &LOCK_EX unless defined $flags;
    flock_db (%$href, $flags) if $flags;
}
sub untie_unlock (\%) {
    my ($href) = @_;
    flock_db (%$href, &LOCK_UN ());
    untie %$href;
}

sub clean {
    local (*D);
    my $fn;

    opendir (D, "$QDIR") || goto release;
    while (defined ($fn = readdir(D))) {
	if ($fn =~ /^(\Q$QNAM\E.*)/) {
	    unlink "$QDIR/$1";
	}
    }
    closedir (D);

  release:
    if ($lockcount > 0) {
	$lockcount = 1;
	&unlock_user ($lockuser);
    }
}

sub leave {
    my $exitcode = shift;
    &clean;
    if ($QMAIL_CODES) {
	if ($exitcode == 71 || $exitcode == 74 || $exitcode == 75) {
	    $exitcode = 111;
	}
	elsif ($exitcode) {
	    $exitcode = 100;
	}
	    
    }
    exit ($exitcode);
}

sub rollback {
    if ($msgmd5) {
	my %rpc;
	tie_lock (%rpc, $REPLAY);
	delete $rpc{$msgmd5};
	untie_unlock (%rpc);
    }
}

sub handler {
    &rollback;
    kill 15, $pgppid if $pgppid;
    &leave (75);
}

sub fatal {
    printf @_[1..$#_];
    &leave ($_[0]);
}

sub runpgp ($;$$) {
    my ($cmd, $passphrase) = @_;
    my ($ret, $out, $oldflush);
    local (*LF);

    pipe (RPP, WPP) || die "pipe failed" if ($passphrase);
    pipe (ROP, WOP) || die "pipe failed";
    if ($PGPLOCK) {
	open LF, ">$PGPLOCK";
	flock LF, &LOCK_EX;
    }
    $oldflush = $|;        # Flush STDOUT before forking
    $| = 1;
    print "";
    unless ($pgppid = fork) {
	close LF;
	close ROP;
	#print (STDERR "+ $PGP +batchmode +force +verbose=0 $cmd\n");
	open (STDOUT, ">&WOP") || die "couldn't reopen stdout";
	open (STDERR, ">&WOP") || die "couldn't reopen stdout";
	close (STDIN);
	close WOP;
	if ($passphrase) {
	    close WPP;
	    $ENV{'PGPPASSFD'} = fileno RPP;
	}
	unless (exec ("$PGP +batchmode +force +verbose=0 +armorlines=0"
		      . " $cmd")) {
	    print STDERR "Exec of PGP failed.\n";
	    exit (1);
	}
    }
    $| = $oldflush;
    close WOP;
    # Be prepared for PGP to hang
    alarm (120);
    if ($passphrase) {
	close RPP;
	print WPP "$passphrase\n";
	close WPP;
    }
    $out = "";
    while (<ROP>) {
	$out .= $_;
    }
    close (ROP);
    waitpid ($pgppid, 0);
    undef $pgppid;
    alarm (0);
    $ret = $?;
    if ($PGPLOCK) {
	flock LF, &LOCK_UN;
	close LF;
    }
    # printf STDERR "PGP status: 0x%x\n", $ret;
    $_[2] = $out;
    return ($ret>>8);
}

my @BINCHARS = ('-', '0' .. '9', 'A' .. 'Z', '_', 'a' .. 'z');
sub armor3bytes {
    my ($val) = @_;
    my $str = "";
    my $i;
    for ($i = 0; $i < 4; $i++) {
	$str .= $BINCHARS[$val&0x3f];
	$val >>= 6;
    }
    return $str;
}
# lineofgarbage generates text that should be hard to compress, not
# that is cryptographically random.
srand 0;
sub lineofgarbage {
    my ($str, $i) = ("");
    for ($i = 0; $i < 16; $i++) {
	$str .= armor3bytes (int (rand 0x1000000));
    }
    return $str;
}
sub mkmsgid {
    my $tv = pack ("x16");
    syscall (&SYS_gettimeofday, $tv, undef);
    my ($now, $usec) = unpack ("L2", $tv);
    my $id = $BINCHARS[($usec>>6) & 0x3f] . $BINCHARS[$usec & 0x3f];
    foreach ($now, (($now >> 24) & 0x7f) | ($$ << 8)) {
	$id .= &armor3bytes ($_);
    }
    return $id . &randomstr;
}
sub rcvdline {
    my ($user, $plus) = @_;
    my $msgid = &mkmsgid;
    return ("Received: by $HOSTNAME with unique id $msgid for "
	    . "<$user" . ($plus ? $plus : "") . "\@$HOSTNAME>; "
	    . scalar (gmtime) . " +0000 (GMT)\n", $msgid);
}

sub filecost ($) {
    my $file = shift;
    my $size = (stat $file)[7];
    return 1 unless $size;
    return 1 + int ($size/$MSGSZUNIT);
}

my $BGARBAGE = "-----BEGIN GARBAGE-----\n";
my $EGARBAGE = "-----END GARBAGE-----\n";
my $MIMEHDR = <<"EOF";
References: <%s>
Subject: Partial message (part %d of %d)
X-Garbage: %s
Content-type: message/partial; id=\"%s\"; number=%d; total=%d
MIME-Version: 1.0

EOF
sub remail {
    my ($file, $sign, $pubring, $rbfile, $fixedsz) = @_;
    my ($nrbused, $ascfile, $err) = (0);

    if ($pubring) {
	$ascfile = "$file.asc";
	unlink ("$ascfile");
	&runpgp (($sign ?
		  "-seat +pubring=$pubring -u $HOSTNAME" :
		  "-eat +pubring=$pubring +secring=/dev/null")
		 . " $file 0x -o $ascfile", $PASSPHRASE, $err);
    } else {
	$ascfile = "$file";
	$err = "Fatal internal error.\n";
    }
    &fatal (0, "Encrypt/sign file:\n$err")
	unless (-f "$ascfile");

    open (RB, "<$rbfile") || &fatal (0, "Can't open reply block file.\n");
    open (M, "<$ascfile") || &fatal (0, "Missing message file?\n");

    my @breakpos = (0);
    my $padbytes;
    if ($fixedsz) {
	my $len = 0;
	while (<M>) {
	    if ($len + length > $MSGSIZE) {
		fatal (0, "Line too long!\n") if ($len <= 0);
		push @breakpos, $breakpos[$#breakpos] + $len;
		$len = 0;
	    }
	    $len += length;
	}
	$padbytes = $MSGSIZE - $len;
    }
    my $partno = 0;
    my $nparts = @breakpos;
    while (@breakpos) {
	my $line;
	my %rnd;
	my %pr;

	$partno++;
	seek (RB, 0, 0);
	for ($line = <RB>;
	     $line && $line =~ /^Reply-Block:\s*(([a-z])=(0.\d+))?/i;) {
	    my ($set, $val) = ($2, $3);
	  resend:
	    my $pos = $breakpos[0];
	    seek (M, $pos, 0);

	    if ($set) {
		if (!defined ($rnd{$set})) {
		    $rnd{$set} = &randomfloat;
		    $pr{$set} = 0.0;
		}
		if ($pr{$set} < $rnd{$set} && $pr{$set} + $val >= $rnd{$set}) {
		    $nrbused++;
		    open (RM, "| $REMAIL");
		}
		else {
		    open (RM, ">/dev/null");
		}
		$pr{$set} += $val;
	    }
	    else {
		$nrbused++;
		open (RM, "| $REMAIL");
	    }
	    print RM "From nobody\@$HOSTNAME\n\n";
	    while (defined ($line = <RB>) && $line !~ /^Reply-Block:/i) {
		print RM $line;
	    }

	    if ($fixedsz && $nparts > 1) {
		my ($n, $garbage) = (0, "");
		$n = $MSGSIZE - ($breakpos[1] - $breakpos[0])
		    if ($breakpos[1]);
		$n += 2 if ($partno < 10);
		$n += 2 if ($nparts < 10);
		while (length ($garbage) < $n) {
		    $garbage .= substr (&lineofgarbage, 0, $n);
		}
		printf RM ($MIMEHDR, $rmsgid, $partno, $nparts, $garbage,
			   $rmsgid, $partno, $nparts);
	    }
	    while (<M>) {
		print RM $_;
		if ($breakpos[1]) {
		    $pos += length;
		    last if ($pos >= $breakpos[1]);
		}
	    }
	    if ($fixedsz && $partno == $nparts) {
		my $n = $padbytes - length ($BGARBAGE . $EGARBAGE);
		if ($nparts == 1) {
		    $n += length ($MIMEHDR) + 16 - 2;
		}
		if ($n > 0) {
		    print RM $BGARBAGE;
		    while ($n > 65) {
			print RM &lineofgarbage, "\n";
			$n -= 65;
		    }
		    print RM substr (&lineofgarbage, 0, $n - 1), "\n"
			if ($n > 0);
		    print RM $EGARBAGE;
		}
		elsif ($padbytes > 0) {
		    print RM "-" x ($padbytes - 1), "\n";
		}
	    }
	    close (RM) || fatal (0, "Couldn't write to remailer.\n");
	    if ($set && $pr{$set} >= 1.0) {
		$val = $pr{$set} - int ($pr{$set});
		$pr{$set} = 0.0;
		$rnd{$set} = &randomfloat;
		goto resend if ($val > 0.0);
	    }
	}
	shift @breakpos;
    }
    close (RB);
    close (M);
    return $nrbused * ($fixedsz ? $nparts : filecost ($ascfile));
}

sub sendtouser {
    my ($user, $file, $dontsign, $newrb) = @_;
    my $flags = (&read_user_dat ($user))[3];
    my $crypt = ($flags & $FL_ENCRECV);
    my $rb = $newrb ? "$NDIR/$user.nrb" : "$NDIR/$user.rb";

    return &remail ($file, !$dontsign && $crypt,
		    $crypt ? "$NDIR/$user.pgp" : undef,
		    $rb, $flags & $FL_FIXEDSZ)
	if $rb;
    return 0;
}

sub decrypt_stdin {
    my $err;
    open (I, ">$QPREF.i") || &fatal (71, "Error creating queue file ($!).\n");
    while (<STDIN>) { last if /^-----BEGIN PGP MESSAGE-----\s*$/; }
    while ($_) {
	&fatal (71, "Error writing queue file ($!).\n") unless print I $_;
	last if (/^-----END PGP MESSAGE-----\s*$/ || ! ($_ = <STDIN>));
    }
    &fatal (71, "Error writing queue file ($!).\n") unless close (I);

    &runpgp ("-b $QPREF.i -o $QPREF.m", $PASSPHRASE, $err);
    &fatal (66, "Could not decrypt message.\n", $err)
	unless (-f "$QPREF.m");
}

my $TODAY;
sub day_number () {
    $TODAY = int (time / (60 * 60 * 24)) unless defined ($TODAY);
    return ($TODAY);
}

sub lock_user {
    my ($user) = @_;
    if ($lockcount > 0) {
	if ($user ne $lockuser) {
	    &fatal (70, "Attempt to lock multiple users.\n");
	}
	else {
	    $lockcount++;
	    return 1;
	}
    }
    $lockuser = $user;
    do {
	open LOCKFD, ">$NDIR/$user.lock";
	unless (flock (LOCKFD, &LOCK_EX)) {
	    &rollback;
	    &fatal (71, "Can't lock user: $!\n");
	}
    } until ((stat LOCKFD)[3] > 0);
    $lockcount = 1;
    return 1;
}

sub unlock_user {
    my ($user) = @_;
    if (!$lockcount || $lockuser ne $user) {
	&fatal (70, "Attempt to unlock user when not locked.\n");
    }
    if (--$lockcount == 0) {
	flock (LOCKFD, &LOCK_UN);
	if (flock (LOCKFD, &LOCK_EX|&LOCK_NB) && (stat LOCKFD)[3] > 0) {
	    unlink "$NDIR/$user.lock";
	}
	close LOCKFD;
    }
}

sub read_user_dat {
    my $user = lc shift;
    my $today = &day_number;
    my @vals;

    &check_username ($user) || return undef;
    open (DAT, "<$NDIR/$user.dat") || return ($today, 0, $today, $DEFFLAGS);
    $_ = <DAT>;
    unless (@vals = /^(\d+) (\d+) (\d+) (\d+)/) {
	warn "Bad data file $NDIR/$user.dat."; # XXX
	return ($today, 0, $today, $DEFFLAGS);
    }
    $_ = <DAT>;
    chop;
    return (@vals, $_);
}

sub write_user_dat {
    my ($user, $upcount, $upsdate, $flags, $name) = @_;
    my $today = &day_number;
    my $locked;

    &lock_user ($user);
    my @vals = &read_user_dat ($user);
    unless (@vals) {
	&unlock_user ($user);
	return undef;
    }
    if ($today != $vals[0]) {
	$vals[0] = $today;
	$vals[1] = 0;
    }
    if ($upcount > 0) { $vals[1] += $upcount; }
    if ($upcount < 0) { $vals[1] = 0; }
    if ($upsdate) { $vals[2] = $today; }
    if (defined ($flags)) { $vals[3] = $flags; }
    if (defined ($name)) { $vals[4] = $name; }
    my $path = &tmpfile ("$vals[0] $vals[1] $vals[2] $vals[3]\n$vals[4]\n");
    system ("chflags nodump $path");
    sync ($path);
    rename ($path, "$NDIR/$user.dat");
    &unlock_user ($user);
    return $vals[1];
}

sub bump_msg_count {
    my ($user, $inc) = @_;
    write_user_dat ($user, $inc);
    my ($count, $flags) = (read_user_dat ($user))[1,3];
    my $date = gmtime;

    return 1 if ($flags & $FL_NOLIMIT);
    return 1 unless (defined ($count) && $count > $MSGPERDAY);

    $flags |= $FL_DISABLED;
    write_user_dat ($user, 0, 0, $flags);

    &sendtouser ($user, &msgfile ($user, <<"EOF", $count + 1));
From: config\@$HOSTNAME
Date: $date GMT
To: $user\@$HOSTNAME

You have sent sent or received enough mail in one day to exceed the
maximum daily limit.  Your alias account <$user\@$HOSTNAME> has
therefore been disabled.

Please check to make sure this isn\'t a configuration error or a loop
in your reply block.  To reenable your mail alias account, you must
send the following commands, PGP signed and encrypted, to
<config\@$HOSTNAME>:

Config:
From: $user
Nym-Command: -disable
EOF

    return undef;
}

sub parse_address {
    $_ = $_[0];
    /^.*<(\S*)>/ && return $1;
    /^(\S+:)?\s*(\S+)/ && return $2;
    undef;
}

sub reply_hdr {
    my $prio = 0;
    my $sender;
    my $msgid;
    my $hdr;
    my $qhdr = '';

    while (<STDIN>) {
	$qhdr .= "> $_";
	if (/^$/) {
	    last;
	}
	elsif (/^Message-Id:\s*(<\S+>)/) {
	    $msgid = $1;
	}
	elsif (/MAILER-DAEMON/) {
	    return ();
	}
	elsif (/^From\s+(\S+)/ && $prio < 1) {
	    $prio = 1; $sender = $1;
	}
	elsif (/^From:/ && $prio <= 2) {
	    $prio = 2;
	    $sender = &parse_address ($_);
	}
	elsif (/^Reply-To:/) {
	    $prio = 3;
	    $sender = &parse_address ($_);
	}
	elsif (/^X-Loop: $HOSTNAME$/) {
	    return ();
	}
    }
    return () unless ($sender);
    $hdr = "To: $sender\n";
    $hdr .= "References: $msgid\nIn-Reply-To: $msgid\n" if ($msgid);
    $hdr .= "X-Loop: $HOSTNAME\n";
    return ($hdr, $qhdr);
}

sub get_user {
    my ($from) = @_;
    my ($user, $extra);
    ($from =~
     /^From:\s*(\w[\w-]{1,15})(\+[\w-]*)?(@($HOSTNAME)\b[^@]*| [^@]*|)\s*$/i)
	|| return undef;
    $user = $1;
    $extra = $2 ? $2 : "";
    &check_username ($user) || return undef;
    return ($user, $extra);
}

# Calculate some number that grows roughly as the number of days in a
# given date.  This way we can make sure a signature was made at most
# 6-8 days ago (since we will get leap years wrong).
my @dom = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
sub sumtime {
    my ($y, $m, $d) = @_;
    my $i;
    $d += 365 * $y; 
    for ($i = 0; $i < $m; $i++) {
	$d += $dom[$i];
    }
    return ($d);
}

sub check_replay {
    my ($file, $err) = @_;
    my %rpc; # Replay cache

    ($err =~ /^Signature made (\d{4})\/(\d{2})\/(\d{2}) /m) || return (-1);
    my $sigday = &sumtime ($1 - 1900, $2 - 1, $3 + 0);
    my $today = &sumtime ((gmtime)[5,4,3]);
    ($today >= $sigday + $SIGDAYS) && return (1);
    ($sigday > $today + 1)
	&& &fatal (65, "Invalid date on PGP signature\n");

    my $sighash = `$MD5 $file`;
    $sighash =~ s/ .*\n//;

    tie_lock (%rpc, $REPLAY);
    if (defined ($rpc{$sighash})) {
	untie_unlock (%rpc);
	return 1;
    }
    $msgmd5 = $rpc{$sighash};
    $rpc{$sighash} = $sigday;
    $rpc{'.clean'} = 0 unless (defined ($rpc{'.clean'}));
    if ($today > $rpc{'.clean'}) {
	foreach (keys (%rpc)) {
	    delete ($rpc{$_}) if ($today > $rpc{$_} + $SIGDAYS);
	}
	$rpc{'.clean'} = $today;
    }
    untie_unlock (%rpc);
    return undef;
}

sub check_sig {
    my ($pubring, $message) = @_;
    my $err;

    if (&runpgp ("+secring=/dev/null +pubring=$pubring"
		 . " $message.sig $message", undef, $err)
	|| ($err =~
	    /^Good signature from user.*<(config|send)\@$HOSTNAME>/m)) {
	$_[2] = "Invalid PGP signature.\n";
	return undef;
    }
    if (&check_replay ("$message.sig", $err)) {
	&fatal (0, "Discarding replay or old message.\n");
#	$_[2] = "Message replay or invalid date on PGP signature.\n";
#	return undef;
    }
    return 1;
}

sub check_username {
    my ($user) = lc shift;

    if ($user !~ /^\w[\w-]{1,15}$/) {
	$_[1] = "Invalid alias name.\n";
	return undef;
    }
    if (-f "$NDIR/$user.forward" || -f "$NDIR/$user.reply") {
	$_[1] = "Alias $user\@$HOSTNAME is reserved.\n";
	return undef;
    }
    foreach (@RSVD_NAMES) {
	$_ = lc $_;
	if ($user eq $_) {
	    $_[1] = "Alias $user\@$HOSTNAME is reserved.\n";
	    return undef;
	}
    }
    return (1);
}

sub authorize_user {
    my ($user) = @_;
    my $err;

    unless (&check_username ($user , $err)) {
	$_[1] = $err;
	return undef;
    }
    unless (&check_sig ("$NDIR/$user.pgp", "$QPREF.m", $err)) {
	$_[1] = $err;
	return undef;
    }
    &write_user_dat ($user, 0, 1);
    return 1;
}

my $tcnt = 0;
sub tmpfile {
    local *TMP;
    my $path = "$QPREF.t" . $tcnt++;
    unlink ("$path");
    open (TMP, ">$path") || &fatal (70, "Could not create temporary file.\n");
    unless ((printf TMP @_) && (close (TMP))) {
	&fatal (74, "Could not write temporary file.\n");
    }
    return ($path);
}
sub msgfile {
    my ($user, @msg) = @_;
    my ($recvd, $msgid) = &rcvdline ($user);
    return &tmpfile ("%s$msg[0]", $recvd, (@msg[1..$#msg]));
}

sub ccc_delete (\%$) {
    my ($href, $user) = @_;
    my $cookie;
    if ($cookie = $$href{$user}) {
	$cookie =~ s/^\S+\s+//;
	delete ($$href{$cookie});
	delete ($$href{$user});
	return 1;
    }
    return undef;
}
sub ccc_cookie (\%$) {
    my ($href, $user) = @_;
    my $cookie;
    if ($cookie = $$href{$user}) {
	$cookie =~ s/^\S+\s+//;
	return $cookie;
    }
    return undef;
}
sub ccc_new (\%$) {
    my ($href, $user) = @_;
    my $cookie = sprintf "+%08x%08x", randomval, randomval;
    my $today = &day_number;
    ccc_delete (%$href, $user);
    $$href{$user} = "$today $cookie";
    $$href{$cookie} = "$today $user";
    return $cookie;
}
sub ccc_clean () {
    my ($key, $val, $day, $u);
    my $date = gmtime;
    my $today = day_number;
    my %ccc;
    my @goners;
    my @killednrb;

    tie_lock (%ccc, $CCC);
    foreach $key (keys %ccc) {
	($day, $val) = split /\s+/, $ccc{$key};
	next unless defined ($day) && defined ($val);
	next unless $today > $day + $SIGDAYS;
	delete $ccc{$key};
	if ($key !~ /\+/) {
	    if (-f "$NDIR/$key.rb") {
		wipefile ("$NDIR/$key.nrb");
		push @killednrb, $key;
	    }
	    else {
		push @goners, $key;
	    }
	}
    }
    $ccc{'.clean'} = $today;
    untie_unlock (%ccc);

    my $user;
    foreach $user (@goners) {
	lock_user ($user);
	wipefile ("$NDIR/$user.dat", "$NDIR/$user.nrb",
		  "$NDIR/$user.pgp") unless -f "$NDIR/$user.rb";
	unlock_user ($user);
    }
    foreach $user (@killednrb) {
	&sendtouser ($user, &msgfile ($user, <<"EOF"));
From: confirm\@$HOSTNAME
Date: $date GMT
To: $user\@$HOSTNAME

You submitted a new reply block for your pseudonym a while ago.
However, you never confirmed that reply block.  This is most likely
because the new reply block did not work properly and you never
received confirmation instructions.  However, it may also be because a
message got lost in transit.

In either event, if you still want to update your reply block you
should send a new copy to config\@$HOSTNAME.
EOF
    }
}

sub runconfig {
    my ($user, $pubkey, $rblock, $create, $delete);
    my $err = "";
    my $cmds = "";

    &decrypt_stdin;

    open (M, "<$QPREF.m")
	|| &fatal (66, "Could not decrypt message.\n");
    while (<M>) {
	last if (/^Config:/);
	/^$/ || &fatal (0, "Discarding non-config message.\n");
    }
    $_ || &fatal (0, "Discarding empty input message.\n");
  hdrloop:
    while (<M>) {
	if ($. > $MAXLINES) {
	    $err .= "Header exceeds maximum number of lines.\n";
	    last;
	}
	elsif (/^From:/) {
	    if (defined ($user)) {
		$err .= "Duplicate From: line\n";
	    }
	    else {
		$err .= "Message contains CR characters.  "
		    . "Did you forget the -t flag to PGP?\n" if /\r\n/;
		my $extra;
		($user, $extra) = &get_user ($_);
		$user || ($err .= "Illegal/reserved user name or invalid "
			  . "machine name in From: line.\n");
		$extra && ($err .= "Can't send config requests from "
			   . "\"plussed\" addresses\n");
		$user =~ tr/A-Z/a-z/ if ($user);
	    }
	}
	elsif (/^Public-Key:/i) {
	    if (defined ($pubkey)) {
		$err .= "duplicate Public-Key: line\n";
	    } else {
		$pubkey = "";
		while (<M>) {
		    $pubkey .= $_;
		    last if /^-----END/;
		    if ($. > $MAXLINES) { undef ($pubkey); redo hdrloop; }
		}
	    }
	}
	elsif (/^Reply-Block:/i) {
	    my $blank = 1;
	    $rblock = $_;
	    while (<M>) {
		if ($. > $MAXLINES) { undef ($rblock); redo hdrloop; }
		s/\r$//;
		if (/^Reply-Block:/i && !$blank) { $rblock .= "\n"; }
		$rblock .= $_;
		$blank = /^$/;
	    }
	    $rblock .= "\n" unless ($blank);
	}
	elsif (/^Nym-Commands?:(.*)/i) {
	    $cmds .= "$1\n";
	}
	elsif (/^([\w-]+:)/) {
	    $err .= "Unknown header \"$1\".\n";
	}
    }
    close (M);

    my ($rbfile, $pubring, $pgperr, $flags);

    if ($rblock) {
	$rbfile = "$QPREF.rb";
	open (RB, ">$rbfile")
	    || &fatal (70, "Can't open reply block file ($!)\n");
	&fatal (74, "Error updating reply block ($!).\n")
	    unless ((print RB $rblock) && close (RB));
	system ("chflags nodump $QPREF.rb");
    }
    if ($pubkey) {
	$pubring = "$QPREF.pgp";
	system ("cp $RINGPROTO $pubring");
	open (ASC, ">$QPREF.asc")
	    || &fatal (70, "Can't open public key file ($!)\n");
	select ((select (ASC), $| = 1)[$[]);
	&fatal (74, "Error updating public key file ($!).\n")
	    unless ((print ASC $pubkey) && close (ASC));
	if (&runpgp ("-ka +secring=/dev/null"
		     . " +pubring=$pubring"
		     . " $QPREF.asc", undef, $pgperr)
	    || $pgperr !~ /^\s*1 new key/m) {
	    $err .= "Error setting new public key:$pgperr\n";
	    undef ($pubring);
	}
	else {
	    chmod (0660, "$QPREF.pgp");
	    system ("chflags nodump $QPREF.pgp");
	}
    }

    my $incctr = 0;
    my $fullname;

    $user && &lock_user ($user);

    if ($user && $cmds) {
	my $rest = $cmds;
	$flags = (&read_user_dat ($user))[3];
	while ($rest =~ /^\s*([\w+-]+[=?]?)/) {
	    $_ = $1;
	    $rest = $';
	    if (/^(\+|-)(\w+)$/) {
		my $val;
		if ($2 eq "acksend") {
		    $val = $FL_ACKSEND;
		}
		elsif ($2 eq "cryptrecv") {
		    $val = $FL_ENCRECV;
		}
		elsif ($2 eq "signsend") {
		    $val = $FL_SIGSEND;
		}
		elsif ($2 eq "disable") {
		    $val = $FL_DISABLED;
		    #$incctr = -1 if ($1 eq "-");
		}
		elsif ($2 eq "fixedsize") {
		    $val = $FL_FIXEDSZ;
		}
		elsif ($2 eq "fingerkey") {
		    $val = $FL_FINGERKEY;
		}
		elsif ($2 eq "nobcc") {
		    $val = $FL_NOBCC;
		}
		else {
		    $err .= "Invalid Nym-Command switch `$1' in `$1$2'.\n";
		    next;
		}
		if ($1 eq "+") {
		    $flags |= $val;
		}
		else {
		    $flags &= ~$val;
		}
	    }
	    elsif ($_ eq "name=") {
		unless ($rest =~ /^\"(([^\\\"$;\n]|\\\\|\\\")*)\"\s/) {
		    $err .= "Could not parse your name=\"...\" Nym-Command.\n";
		    $rest = "";
		    last;
		}
		$rest = $';
		$fullname = $1;
		$fullname =~ s/\\\"/\"/g;
		$fullname =~ s/\\\\/\\/g;

		$err .= "Full names cannot contain unprintable characters.\n"
		    if $fullname =~ /[\x00-\x1f\x7f-\x9f\xff]/;

		my $s = $fullname;
		$s =~ s/\\./../g;
		$s =~ s/\"[^\"]*\"//g;
		$err .= <<"EOF" if $s =~ /[@\",<>]/;
Full names cannot have unbalanced '\"' characters or unquoted
    '<', '>', '\@', or ',' characters in name= Nym-Commands.
EOF

                $err .= "Full name is too long.\n"
		    if length ($fullname) > 255;
	    }
	    elsif ($_ eq "delete") {
		$delete = 1;
	    }
	    elsif ($_ eq "create") {
		$create = 1;
	    }
	    elsif ($_ eq "create?") {
		$create = 1 unless -f "$NDIR/$user.pgp";
	    }
	    else {
		$err .= "Invalid Nym-Command `$_'.\n";
		$rest =~ s/^\"(([^\\\"$;\n]|\\\\|\\\")*)\"\s//;
	    }
	}
	if ($rest =~ /^\s*(\S[^\n\r]*)/) {
	    $err .= "Could not parse Nym-Command `$1'.\n";
	}
    }

    $err .= "$HOSTNAME is not currently granting new aliases.\n"
	if ($create && $NOCREATE);

    my $authorized;

    if ($user) {
	if (! $create) {
	    if (-f "$NDIR/$user.pgp") {
		($authorized = &authorize_user ($user, $pgperr))
		    || ($err .= "$pgperr ");
	    }
	    else {
		$err = "No such user.  Use \"Nym-Command: create\" to "
		    . "create a new alias.\n";
	    }
	}
	else {
	    $err .= "Can't use delete Nym-Command with create.\n"
		if ($delete);
	    $rbfile || ($err .= "You must specify at least one reply-block"
			. " with \"Reply-Block\".\n");
	    if ($pubring) {
		&check_sig ($pubring, "$QPREF.m", $pgperr)
		    || ($err .= "$pgperr  (when checking against the public"
			. "key in your message)\n");
	    }
	    else {
		$err .= "You must specify a PGP public key with"
		    . " \"Public-Key:\".\n";
	    }
	    if ($err || -f "$NDIR/$user.pgp") {
		$err .= "The username you chose is already in use.\n"
		    unless ($err);
	    }
	}
    }
    else {
	$err .= "No/bad From: line designating Nym.\n";
    }

    my $date = gmtime;

    if ($err) {
	$user && &unlock_user ($user);
	my $file = &msgfile ($user ? $user : "UNKNOWN ALIAS", <<"EOF",
From: config\@$HOSTNAME
Date: $date GMT
To: %s%s

Your request to modify or create %s could
not be performed.  The following error(s) were encountered:

%s
EOF
			     $user ? "$user\@$HOSTNAME"
			     : "UNKNOWN ALIAS",
			     $authorized ? "" : " (unauthentic)",
			     $user ? "alias <$user\@$HOSTNAME>"
			     : "an unspecified alias", $err);
	if ($authorized && !$rbfile) {
	    &sendtouser ($user, $file);
	}
	elsif ($rbfile) {
	    &remail ($file, $authorized,
		     $authorized ? "$NDIR/$user.pgp" : $pubring,
		     $rbfile);
	}
	&fatal (0, $err);
    }

    my %ccc;

    if ($delete) {
	my $usenrb = "";
	&fatal (0, "Can't delete when not authorized!\n")
	    unless ($authorized);
	$SIG{'TERM'} = 'IGNORE';
	unlink ("$QPREF.pgp");
	if ($CONFIRM) {
	    tie_lock (%ccc, $CCC);
	    ccc_delete (%ccc, $user);
	    untie_unlock (%ccc);
	    $usenrb = "n" if (-f "$NDIR/$user.nrb");
	}
	unless (-f "$QPREF.rb") {
	    rename (("$NDIR/$user." . $usenrb . "rb"), "$QPREF.rb")
		|| &fatal (0, "rename .rb file failed\n");
	}
	wipefile ("$NDIR/$user.rb", "$NDIR/$user.nrb", "$NDIR/$user.dat");
	rename ("$NDIR/$user.pgp", "$QPREF.pgp")
	    || &fatal (0, "rename .pgp file failed\n");
	&unlock_user ($user);

	&remail (&msgfile ($user, <<"EOF"), 1, "$QPREF.pgp", "$QPREF.rb");
From: config\@$HOSTNAME
Date: $date GMT
To: $user\@$HOSTNAME

This message is to confirm that pseudonym <$user\@$HOSTNAME>
was deleted on $date GMT.  Your reply-block
and PGP key will be wiped once this message is mailed.
EOF

	wipefile ("$QPREF.rb", "$QPREF.pgp");
	&leave (0);
    }

    my ($cmsg, $cookie) = ("");
    tie_lock (%ccc, $CCC) if ($CONFIRM);
    $SIG{'TERM'} = 'IGNORE';
    if ($pubring) {
	saferename ("$pubring", "$NDIR/$user.pgp");
    }
    if ($rbfile) {
	if ($CONFIRM) {
	    ccc_new (%ccc, $user);
	    saferename ("$rbfile", "$NDIR/$user.nrb");
	}
	else {
	    saferename ("$rbfile", "$NDIR/$user.rb");
	}
    }
    &write_user_dat ($user, $incctr, 1, $flags, $fullname);
    &unlock_user ($user);
    my $replyto = '';
    if ($CONFIRM && ($cookie = ccc_cookie (%ccc, $user))) {
	$replyto = "Reply-To: confirm$cookie\@$HOSTNAME\n";
	$cmsg = <<"EOF";

A new reply block has been received for your mail alias, but has not
yet been activated.  In order to start receiving mail with your new
reply block, you must confirm it by sending an (anonymous) E-mail
message to the following address:

   confirm$cookie\@$HOSTNAME

The contents of the message can be anything.  Any message delivered to
this address will activate your reply block.

EOF
    }
    my $doclean = ($CONFIRM && !($ccc{'.clean'}
				 && $ccc{'.clean'} == &day_number));
    untie_unlock (%ccc) if ($CONFIRM);
    &sendtouser ($user,
		 &msgfile ($user, $replyto . <<"EOF" . $cmsg), undef,
From: config\@$HOSTNAME
Date: $date GMT
To: $user\@$HOSTNAME

Your configuration request completed successfully.
EOF
		 defined ($cookie));
    $SIG{'TERM'} = \&handler;
    # Here would be a good place to receive signals.
    $SIG{'TERM'} = 'IGNORE';
    ccc_clean if ($doclean);
    &leave (0);
}

sub runconfirm {
    my $arg = lc shift;
    my ($user, $cookie);
    my $date = gmtime;
    my %ccc;

    (-f $CCC) || fatal (67, "Invalid username\n");
    tie_lock (%ccc, $CCC, 0);
    ($user = $ccc{$arg}) || &leave (0);
    $user =~ s/^\S+\s+//;
    lock_user ($user);
    flock_db (%ccc, &LOCK_EX ());
    delete ($ccc{"c:$arg"});
    (($cookie = ccc_cookie (%ccc, $user)) && $cookie eq $arg)
	|| &leave (0);
    $SIG{'TERM'} = 'IGNORE';
    ccc_delete (%ccc, $user);
    (-f "$NDIR/$user.nrb")
	|| &fatal (70, "No reply block for valid confirmation\n");
    saferename ("$NDIR/$user.nrb", "$NDIR/$user.rb")
	|| &fatal (70, "Cannot install new reply block\n");
    flock_db (%ccc, &LOCK_UN ());
    unlock_user ($user);
    &sendtouser ($user, &msgfile ($user, <<"EOF"));
From: confirm\@$HOSTNAME
Date: $date GMT
To: $user\@$HOSTNAME

Your new reply block has been confirmed and installed.  Your mail
alias is currently active.
EOF

    &leave (0);
}

sub runsend {
    my $user;
    my $date = gmtime;
    my $inhdr;
    my $flags;
    my $hiddento = '';
    my $headerto = '';
    my $resentto = '';
    my $nymcommands = '';
    my $warnings = '';
    my $hasbody;
    my $notmailed = '';

    &decrypt_stdin;

    open (H, ">$QPREF.h");
    open (B, ">$QPREF.b");
    open (M, "<$QPREF.m")
	|| &fatal (66, "Could not decrypt message.\n");
    while (<M>) {
	unless ($inhdr) {
	    /^$/ && next;
	    /^Config:/i && &fatal (0, "Discarding config message to send.\n");
	    $inhdr = 1;
	    /^::$/ && next;
	}
      moreheaders:
	if ($. > $MAXLINES) {
	    &fatal (70, "Header exceeds maximum number of lines.\n");
	}
	elsif (/^From:/) {
	    my $line = $_;
	    my ($name, $extra);

	    &fatal (0, "duplicate From: line\n") if defined ($user);
	    ($user, $extra) = &get_user ($_);
	    $user || &fatal (0, "Illegal user name or invalid "
			     . "machine name in From: line.\n");
	    ($flags, $name) = (&read_user_dat ($user))[3, 4];
	    if ($name) {
		$line = "From: $name <$user$extra\@$HOSTNAME>\n";
	    }
	    else {
		$line = "From: $user$extra\@$HOSTNAME\n";
	    }
	    (print H $line)
		|| &fatal (71, "Error writing queue file ($!).\n");
	    $user =~ tr/A-Z/a-z/;
	    next;
	}
	elsif (/^Hidden-To:(.*)$/i) {
	    $hiddento .= " $1";
	    while (<M>) {
		if (/^[ \t]/) {chomp ($hiddento .= $_);}
		else {goto moreheaders;}
	    }
	}
	elsif (/^(Resent-)?(To|Cc|Bcc):(.*)$/i) {
	    my $rl = $1 ? \$resentto : \$headerto;
	    $$rl .= " $3";
	    (print H $_)
		|| &fatal (71, "Error writing queue file ($!).\n");
	    while (<M>) {
		if (/^[ \t]/) {chomp ($$rl .= $_);}
		else {goto moreheaders;}
		(print H $_)
		    || &fatal (71, "Error writing queue file ($!).\n");
	    }
	}
	elsif (/^Nym-Commands?:(.*)$/i) {
	    $nymcommands .= " $1";
	    while (<M>) {
		if (/^[ \t]/) {chomp ($nymcommands .= $_);}
		else {goto moreheaders;}
	    }
	}
	if (/^$/) {
	    undef $_;
	    last;
	}
	elsif (/^\S/ && !/^\S+:/) {
	    print B $_;
	    $hasbody = 1;
	    undef $_;
	    last;
	}
	(print H $_)
	    || &fatal (71, "Error writing queue file ($!).\n");
    }
    print H "\n" unless defined $_;
    &fatal (65, "No From: line.\n") unless $user;
    foreach (split ' ', $nymcommands) {
	next unless $_;
	/^\+acksend/ && ($flags |= $FL_ACKSEND, next);
	/^\-acksend/ && ($flags &= ~$FL_ACKSEND, next);
	/^\+signsend/ && ($flags |= $FL_SIGSEND, next);
	/^\-signsend/ && ($flags &= ~$FL_SIGSEND, next);
	$warnings .= "Ignored unknown nym-command `$_' (non-fatal).\n";
    }
    close (H) || &fatal (71, "Error writing queue file ($!).\n");
    while (<M>) {
	$hasbody = 1 if !$hasbody && /./;
	print B $_
	    || &fatal (71, "Error writing queue file ($!).\n");
	if ($hasbody) {
	    copyfile (*M, *B);
	    last;
	}
    }
    close (M);

    print B <<"EOF" if ($flags & $FL_SIGSEND && $hasbody);

~~~
This PGP signature only certifies the sender and date of the message.
It implies no approval from the administrators of $HOSTNAME.
Date: $date GMT
From: $user\@$HOSTNAME
EOF
    close (B) || &fatal (71, "Error writing queue file ($!).\n");

    &authorize_user ($user)
	|| &fatal (0, "Invalid PGP signature on message\n");

    if ($CONFIRM && ! -f "$NDIR/$user.rb" && -f "$NDIR/$user.nrb") {
	my %ccc;
	my $cookie;

	lock_user ($user);
	tie_lock (%ccc, $CCC, &LOCK_SH ());
	$cookie = ccc_cookie (%ccc, $user);
	untie_unlock (%ccc);
	if (! -f "$NDIR/$user.rb" && -f "$NDIR/$user.nrb" && $cookie) {
	    &sendtouser ($user, &msgfile ($user, <<"EOF"), undef, 1);
Reply-To: confirm$cookie\@$HOSTNAME
From: send\@$HOSTNAME
Date: $date GMT
To: $user\@$HOSTNAME

You have attempted to send a message through send\@$HOSTNAME.
However, the message could not be resent because your alias does not
yet have an active reply block.  To activate your reply block and make
your alias functional, you must send E-mail (anonymously) to this
address:

   confirm$cookie\@$HOSTNAME

The contents of the mail you send is not important.  Any message
delivered to this address will activate your reply block.

EOF
	    &fatal (0, "Reply block not activated.\n");
	}
	unlock_user ($user);
    }

    if ($flags & $FL_DISABLED) {
	$notmailed = 'NOT ';
	$warnings .= "Your nym account is disabled.\n"
	    . "Send -disable Nym-Command to reenable.\n";
    }

    my $result;
    my @recips;

    my $err;
    if (!$notmailed && ($flags & $FL_SIGSEND) && $hasbody) {
	&fatal (78, "Could not create PGP signature.\n$err")
	    if (&runpgp ("-sat $QPREF.b", $PASSPHRASE, $err)
		|| ! -f "$QPREF.b.asc");
    }
    else {
	rename "$QPREF.b", "$QPREF.b.asc";
    }

    open (H, "<$QPREF.h");
    open (B, "<$QPREF.b.asc");

    if ($hiddento) {
	@recips = grep {$_} split /[\s,]+/, $hiddento;;
	unless (@recips) {
	    $notmailed = 'NOT ';
	    $warnings .= "No valid recipients in Hidden-To: header.\n";
	}
    }
    if ($notmailed) {
	open (SEND, ">/dev/null");
    }
    elsif ($hiddento) {
	open (SEND, "|-")
	    || exec ($SENDMAIL, "-f", "$user\@$HOSTNAME",
		     "-os", "-oem", "-oi", "--", (@recips))
		|| &fatal (1, "Couldn't run $SENDMAIL @recips\n");
    }
    else {
	open (SEND, "| $SENDMAIL -f $user\@$HOSTNAME -os -oem -oi -t");
    }
    copyfile (*H, *SEND);
    copyfile (*B, *SEND);

    $result = close (SEND);
    unless ($notmailed) {
	my ($nrecips, $to) = (1);
	($to = $hiddento) || ($to = $resentto) || ($to = $headerto);
	$to =~ s/\([^\)]*\)//;
	if ($to) {
	    my @rl = split /[\s,]+/, $to;
	    $nrecips = @rl;
	}
	bump_msg_count ($user, $nrecips, filecost ("$QPREF.b.asc"));
    }
    undef $msgmd5;

    if ($result && ($flags & $FL_ACKSEND)
	|| $hiddento && !@recips || $warnings || $notmailed) {
	seek H, 0, 0;
	open ACK, ">$QPREF.a";
	print ACK (&rcvdline ($user))[0];
	print ACK <<"EOF";
From: send\@$HOSTNAME
Date: $date GMT
To: $user\@$HOSTNAME

EOF
   	if ($hiddento) {
	    if (@recips) {
		print ACK <<"EOF", "\t", join (",\n\t", @recips), "\n";
A message with the following header was ${notmailed}remailed to these
recipients under your pseudonym:
EOF
	    }
	    else {
		print ACK <<"EOF";
The message you sent with the following header could not be remailed
because no valid recipients were found in the 'Hidden-To:' header.
EOF
	    }
        } 
	else {
	    print ACK <<"EOF";
This is to acknowledge that a message with the following header was
${notmailed}remailed under your pseudonym:
EOF
	}
	print ACK "\n";
	while (<H>) { print ACK $_; }
	print ACK "\nSome problems were encountered with your "
	    . "message:\n\n", $warnings if ($warnings);
	close (ACK);
	&sendtouser ($user, "$QPREF.a");
    }

    close (H);
    close (B);
    &leave (0);
}

sub runreceive {
    my ($user, $extra) = @_;
    $extra = "" unless (defined ($extra));
    my $date = gmtime;
    my $flags = (&read_user_dat ($user))[3];
    my ($recip, $rrecip) = ('', '');

    if ($flags & $FL_DISABLED) {
	write_user_dat ($user, 1);
	&fatal (69, "Account disabled.\n");
    }

    open (I, ">$QPREF.i") || &fatal (71, "Error creating queue file ($!).\n");
    my $rcvd;
    $extra = '' unless defined $extra;
    ($rcvd, $rmsgid) = &rcvdline ($user, $extra);
    print I $rcvd;
    while (<STDIN>) {
      restart:
	s/^From /X-From: /;
	&fatal (71, "Error writing queue file ($!).\n") unless print I $_;
	last if /^(\s*|[^\s:]+(\s.*)?)$/;
	if (/^(Resent-)?(To|Cc):(.*)$/i) {
	    my $rp = $1 ? \$rrecip : \$recip;
	    $$rp .= $3;
	    while (<STDIN>) {
		goto restart unless /^\s/;
		&fatal (71, "Error writing queue file ($!).\n")
		    unless print I $_;
		$$rp .= $_;
	    }
	}
    }

    if (!$extra && ($flags & $FL_NOBCC)) {
	my $erecip = "$user$extra\@$HOSTNAME";
	$recip = $rrecip if $rrecip;
	unless ($recip =~ /\b\Q$erecip\E\b/i) {
	    &fatal (77, <<"EOF");
This user does not wish to receive blind carbon copies.  You must
specify the user\'s full E-mail address in a To or Cc mail header.
EOF
	}
    }

    copyfile (*STDIN, *I);
    print I <<"EOF" if ($flags & $FL_ENCRECV);

~~~
This PGP signature only certifies the receipt and date of the message.
It implies no approval from the administrators of $HOSTNAME.
Date: $date GMT
To: $user\@$HOSTNAME
EOF
    close (I) || &fatal (71, "Error writing queue file ($!).\n");

    my $nmsg = &sendtouser ($user, "$QPREF.i", !($flags & $FL_ENCRECV));
    bump_msg_count ($user, $nmsg);

    &leave (0);
}

sub usage {
    my $prog = $0;
    $prog =~ s/.*\///;
    fatal (64, <<"EOF");
Usage: $prog -d user
       $prog -fingerd
       $prog -wipe user ...
       $prog -expire [-f]
EOF
}

sub usednyms () {
    opendir (D, $NDIR) || return ();
    my $last = '';
    my @list = grep ({($last ne $_, ($last = $_))[0]}
		     (sort @RSVD_NAMES,
		      grep (s/^(.*)\.(pgp|forward|reply)$/$1/, readdir D)));
    closedir (D);
    return @list;
}

sub rundeliver {
    chop ($PASSPHRASE = catfile ($PASSPHRASEFILE));
    &clean;
    fatal (64, "Usage: nymserv -d recipient\n") unless (@ARGV == 1);
    fatal (67, "Invalid username\n")
	unless ($ARGV[0] =~ /^(\w[\w-]{1,15})(\+[\w-]*)?$/);
    my $recip = lc $1;
    my $plussed = $2;

    if ($recip eq "nobody") {
	&leave (0);
    }
    elsif ($recip eq "config") {
	&runconfig;
    }
    elsif ($recip eq "send") {
	&runsend;
    }
    elsif ($recip eq "confirm" && $plussed) {
	&runconfirm ($plussed);
    }
    elsif ($recip =~ /^(list|used)$/) {
	my ($H, $Q) = &reply_hdr;
	&leave (65, "No valid return address found\n") unless $H;
	my @list = &usednyms;
	open SM, "| $SENDMAIL -oi -f nobody\@$HOSTNAME -t";
	print SM $H;
	print SM "Subject: list of used nyms on $HOSTNAME\n";
	print SM "From: used nyms <nobody\@$HOSTNAME>\n\n";
	print SM join ("\n", @list), "\n";
	print SM "\n", $Q if ($QUOTEREQ);
	&leave (0);
    }
    elsif (-r "$NDIR/$recip.forward") {
	my $inb;
	my $to;
	chop ($to = `cat $NDIR/$recip.forward`);
	($to =~ /^(.*)$/) && ($to = $1);
	if ($to =~ /^\|(.*)/) {
	    exec $1 || &fatal (72, "Exec of $1 failed\n");
	}
	open SM, "| $SENDMAIL -oi -f nobody\@$HOSTNAME -- $to";
	while (<STDIN>) {
	    unless ($inb) {
		s/^From /X-From: /;
		s/^(Return-Receipt-To:)/X-$1/i;
		s/^(Notice-Requested-Upon-Delivery-To:)/X-$1/i;
		s/^(Errors-To:)/X-$1/i;
		$inb = 1 if (/^$/);
	    }
	    print SM $_;
	}
	close (SM);
	&leave (0);
    }
    elsif (-f "$NDIR/$recip.reply") {
	my ($H, $Q) = &reply_hdr;
	&leave (65, "No valid return address found\n") unless $H;
	open SM, "| $SENDMAIL -oi -f nobody\@$HOSTNAME -t";
	print SM $H;
	open F, "<$NDIR/$recip.reply";
	while (<F>) {
	    print SM $_;
	}
	print SM "\n", $Q if ($QUOTEREQ);
	close (F);
	close (SM);
	&leave (0);
    }
    elsif (-r "$NDIR/$recip.pgp") {
	(-r "$NDIR/$recip.rb") || &fatal (69, "Account disabled.\n");
	&runreceive ($recip, $plussed);
    }
    else {
	fatal (67, "Invalid username\n");
    }
    &leave (0);
}

sub runfingerd {
    my ($target, $warning, $fingerdir);
    my $BLURB = ucfirst <<"EOF";
$HOSTNAME offers untraceable E-mail pseudonyms.  Finger
help\@$HOSTNAME for more information about this service,
or visit http://www.cs.berkeley.edu/~raph/n.a.n.html.
EOF

    $SIG{'ALRM'} = sub {&fatal (1, "fingerd timed out\n");};
    alarm (30);

    $target = <STDIN>;
    if ($target) {
	$target =~ s/\r?\n//;
    } else {
	$target = '';
    }

    if ($target =~ /(.*)@([^@]+)/) {
	my ($user,$host,$port,$ipaddr,$sin,$myaddr) = ($1, $2);
	$host .= "." unless $host =~ /\d{1,3}(\.\d{1,3}){1,3}/;
	&fatal (1, "unknown host: %s\n", $host)
	    unless ($ipaddr = inet_aton ($host));
	&fatal (1, "internal error: unknown service finger\n")
	    unless ($port = getservbyname ('finger', 'tcp'));
	socket (SOCK, PF_INET, SOCK_STREAM, getprotobyname ('tcp'))
	    || &fatal (1, "internal error: could not create socket\n");
	$sin = sockaddr_in ($port, $ipaddr);
	printf "[finger %s@%s]\n", $user, $host;
	$myaddr = (unpack_sockaddr_in (getsockname (STDIN)))[1];
	bind (SOCK, sockaddr_in (0, $myaddr))
	    || &fatal (1, "internal error: can't bind socket\n");
	&fatal (1, "Connection refused while connecting to %s\n", $host)
	    if ($ipaddr eq INADDR_LOOPBACK);
	connect (SOCK, $sin)
	    || &fatal (1, "$! while connecting to %s\n", $host);
	select ((select (SOCK), $| = 1)[$[]);
	printf SOCK "%s\r\n", $user;
	while (<SOCK>) {
	    print;
	}
	exit (0);
    }

    $target =~ tr/A-Z/a-z/;
    $target =~ s/^\/w//;		# RFC 742 is weird

    if ($target =~ /^([\w][\w-]{0,15})$/) {
	$target = $1;
    }
    else {
	if ($target) {
	    print "finger: $target: no such user.\n";
	}
	else {
	    print $BLURB;
	    print <<"EOF";

In addition to fingering individual E-mail aliases, you can finger:
    remailer-key - Public key for the $HOSTNAME nym server.
    help         - Help file for the $HOSTNAME nym server.
    list         - List of taken pseudonyms.

EOF
			}
	exit;
    }

    $target = 'remailer-key' if ($target eq 'config' || $target eq 'send');

    if ($target =~ /^(list|used)$/) {
	unless (chdir ($NDIR)) {
	    print "No information on $target.\n";
	    exit;
	}
	print "List of pseudonyms in use on $HOSTNAME:\n\n";
	print join("\n", &usednyms), "\n";
    }
    elsif (-r "$NDIR/$target.reply") {
	unless (open (DATA, "<$NDIR/$target.reply")) {
	    print "No information on $target.\n";
	    exit;
	}
	while (<DATA>) {
	    last unless /^\S+:/;
	}
	print if $_ && !/^$/;
	print while (<DATA>);
    }
    elsif (-r "$NDIR/$target.forward") {
	printf STDOUT ("Mail Alias:  %-24s  Name:  %s\n", $target, '???');
	print "\n", $BLURB;
    }
    elsif (-r "$NDIR/$target.dat") {
	my ($flags, $fullname) = (&read_user_dat ($target))[3,4];
	printf STDOUT ("Mail Alias:  %-24s  Name:  %s\n", $target,
		       ($fullname && $fullname =~ /\S/) ? $fullname : "???");
	if ($flags & $FL_FINGERKEY) {
	    my $key;
	    &runpgp ("-fkxa '<$target\@$HOSTNAME>' $NDIR/$target.pgp"
		     . " 2> /dev/null", undef, $key);
	    print "PGP Public-Key:\n$key"
		if $key =~ /^-----BEGIN PGP PUBLIC KEY BLOCK-----/;
	}
	print "\n", $BLURB;
    }
    else {
	print "finger: $target: no such user.\n";
    }
    &leave (0);
}

sub runwipe {
    my $user;
    my %ccc;
    tie_lock (%ccc, $CCC, 0);
    foreach $user (@_) {
	unless ($user =~ /^(\w[\w-]*)$/) {
	    warn "bad user: $user";
	    next;
	}
	$user = $1;
	lock_user ($user);
	flock_db (%ccc, &LOCK_EX ());
	ccc_delete (%ccc, $user);
	wipefile ("$NDIR/$user.rb", "$NDIR/$user.nrb", "$NDIR/$user.dat",
		  "$NDIR/$user.pgp");
	flock_db (%ccc, &LOCK_UN ());
	unlock_user ($user);
    }
    untie_unlock (%ccc);
}

sub keyinfo ($;$) {
    my ($ring, $user) = @_;
    my ($result, $bits, $id, $fingerprint);
    $user = "0x" unless defined $user;
    &runpgp ("-kvc $user $ring", undef, $result);
    $result || return ();
    ($bits, $id) = ($result =~ /^pub\s+(\d+)\/(\w+)/m);
    ($fingerprint) = ($result =~ /^\s+Key fingerprint\s*=\s*(\S.*)$/m);
    return ($bits, $id, $fingerprint);
}

sub runexpire {
    my $force = shift;

    $force = undef unless (defined ($force) && $force eq '-f');

    my ($nym, $days);

    my @warn;
    my @expire;

    &day_number;

    opendir N, "$NDIR";
    foreach $nym (grep {/\.dat$/} readdir (N)) {
	$nym =~ s/\.dat$//;
	$days = $TODAY - (&read_user_dat ($nym))[2];
	if ($days > $DELETEAFTER) {
	    push @expire, $nym;
	}
	elsif ($days > $WARNAFTER) {
	    push @warn, $nym;
	}
    }
    closedir N;

    if ($force) {
	&runwipe (@expire);

	foreach $nym (@warn) {
	    my $keyid = (keyinfo ("$NDIR/$nym.pgp"))[1];
	    $keyid = $keyid ? "0x$keyid" : 'yournym_PGP_key_ID';
	    open SM, "|$SENDMAIL -f nobody\@$HOSTNAME -t";
	    print SM <<"EOF";
From: Alias expiration daemon <nobody\@$HOSTNAME>
To: $nym\@$HOSTNAME
Subject: Your mail alias is expiring

In order to clean up abandoned mail aliases or aliases with lost PGP
keys, a daemon periodically deletes pseudonyms which appear to be
unused.  It has been over $WARNAFTER days since the last time
$HOSTNAME received a piece of E-mail signed by your private key.  Your
pseudonym is therefore considered inactive, and will be deleted if it
is still inactive after $DELETEAFTER days.

If you do not wish to have your mail alias deleted, simply send any
piece of E-mail through <send\@$HOSTNAME>, or any configuration
message to <config\@$HOSTNAME>--your pseudonym will then automatically
be renewed.  This may also be a good time update your reply block with
a new list of remailers and Encrypt-Keys, as the list of reliable
remailers can change from month to month and any configuration message
will renew your pseudonym.

Note that receiving mail through your pseudonym does not renew it, as
an abandoned account could still be receiving mail.  In order to renew
your account, you must show the nym server that someone still has
access to your account\'s private PGP key.  Note further that just
changing the mail header of your outgoing mail to show your $HOSTNAME
address will not renew your pseudonym either.  (This is insecure
anyway and so is not recommended in the first place.)

The simplest way to renew your pseudonym is to create a file called,
for instance, renew, with the following contents (indented one space
here for clarity, do not indent it when you create the file):

 Config:
 From: $nym

Then sign and encrypt this message with this pgp command:

 pgp -seat renew config\@$HOSTNAME -u $keyid

Here $keyid corresponds to the hex key ID of the PGP key under
which you created your pseudonym account.  (You can also use the
descriptive name of your PGP key instead of the hex key ID.  If you
are unsure what you named your PGP key, you can check the entire
contents of your keyring with the command pgp -kv.)

The above pgp command will create a file called renew.asc.  You must
then mail the contents of that file to <config\@$HOSTNAME>, either
directly, or, preferably, through some anonymous remailers.  When the
nym server receives your message, it will send you a confirmation
saying 'Your configuration request completed successfully.'  Once you
receive this confirmation, your alias account will have been renewed.

Note:  You must create a new renew.asc file each time you renew your
pseudonym.  Nym.alias.net has a replay cache which prevents an
intercepted message from being replayed multiple times by an attacker.
Thus, each signed renew.asc file will only work once, and will only
work if the date in the PGP signature is current.

If you have any questions about this policy or other problems with
$HOSTNAME, please raise them on the newsgroup alt.privacy.anon-server,
or contact admin\@$HOSTNAME as a last resort.

EOF
            close SM;
	    sleep 2;
	}
    }

    if (@warn || @expire) {
	print "Pseudonym expiration report:\n";
	print "warned: @warn\n\n" if (@warn);
	print "expired: @expire\n" if (@expire);
    }
}

umask (007);
$( = (split /\s+/, $), 2)[0];
$< = $>;
chdir ($HOMEDIR) || die "$HOMEDIR: $!";
$SIG{'ALRM'} = \&handler;

my $flag = shift;
if (!$flag) { &usage; }
elsif ($flag eq '-d') { &rundeliver (@ARGV); }
elsif ($flag eq '-fingerd') { &runfingerd; }
elsif ($flag eq '-wipe') { &runwipe (@ARGV); }
elsif ($flag eq '-expire') { &runexpire (@ARGV); }
else { &usage; }
&leave (0);

