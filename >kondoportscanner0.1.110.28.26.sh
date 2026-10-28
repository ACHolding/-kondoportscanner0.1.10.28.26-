#!/bin/sh
# AC Kondo's Port Scanner 0.1 - shell/Perl polyglot (TCP connect scanner)
# (c) AC Kondo 2026
# Scan only systems you own or have permission to assess.
#
# Usage:
#   chmod +x "ac kondos port scanner 0.1 cli.sh"
#   ./"ac kondos port scanner 0.1 cli.sh" [-p PORTS | -a] [-t SECONDS] [-c N] [-o FILE] [-y] HOST
#
# Find perl on PATH (Homebrew / system), then re-exec as Perl via -x.
PERL=
for c in perl /usr/bin/perl /usr/local/bin/perl /opt/homebrew/bin/perl; do
    if command -v "$c" >/dev/null 2>&1; then
        PERL=$(command -v "$c")
        break
    elif [ -x "$c" ]; then
        PERL=$c
        break
    fi
done
if [ -z "$PERL" ]; then
    echo "AC Kondo's Port Scanner 0.1: perl is required but was not found on PATH." >&2
    exit 127
fi
# Best-effort raise of the fd limit; a full-port sweep needs many sockets.
ulimit -n 4096 2>/dev/null || ulimit -n 2048 2>/dev/null || true
exec "$PERL" -x "$0" "$@"
#!perl
use strict;
use warnings;
use IO::Select;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Getopt::Long qw(GetOptions);
use Time::HiRes qw(time sleep);
use Errno qw(EINPROGRESS ECONNREFUSED EHOSTUNREACH ENETUNREACH);
use Socket qw(
    getaddrinfo getnameinfo NI_NUMERICHOST
    SOCK_STREAM SOL_SOCKET SO_ERROR
);

$| = 1;

my $ME = $0;
$ME =~ s{.*/}{};

my $VERSION = '0.1';
my $NAME    = "AC Kondo's Port Scanner $VERSION";

my ($ports, $ports_given) = ('1-1024', 0);
my ($conc,  $conc_given)  = (100,      0);
my ($timeout, $output, $yes, $all, $help) = (1, '', 0, 0, 0);

GetOptions(
    'p=s'    => sub { $ports = $_[1]; $ports_given = 1 },
    'a|all'  => \$all,
    't=f'    => \$timeout,
    'c=i'    => sub { $conc = $_[1]; $conc_given = 1 },
    'o=s'    => \$output,
    'y|yes!' => \$yes,
    'h|help' => \$help,
) or die "Invalid options. Try: $ME -h\n";

if ($help || @ARGV != 1) {
    print <<"USAGE";
$NAME - TCP connect scanner
Usage: $ME [-p PORTS | -a] [-t SECONDS] [-c N] [-o FILE] [-y] HOST

  -p PORTS     Comma list / ranges, e.g. 22,80,443 or 1-65535 (default: 1-1024)
  -a, --all    Scan all 65535 ports (implies -c 400 unless -c is given)
  -t SECONDS   Per-port connect timeout 0.1-30 (default: 1)
  -c N         Concurrent connects 1-1000 (default: 100)
  -o FILE      Write report to FILE
  -y, --yes    Skip the interactive authorization prompt
  -h, --help   Show this help

Host may be a hostname, an IPv4 address, or an IPv6 address.
Only scan hosts you own or are authorized to test.
USAGE
    exit($help ? 0 : 2);
}

$ports = '1-65535' if $all && !$ports_given;
$conc  = 400       if $all && !$conc_given;

my $target = shift @ARGV;
$target =~ s/\A\s+|\s+\z//g;

my $is_v6 = ($target =~ /:/);
my $literal;
if ($is_v6) {
    $literal = $target;
    $literal =~ s/\A\[|\]\z//g;
    die "Invalid target (bad IPv6 address)\n"
        unless $literal =~ /\A[0-9A-Fa-f:.]+(%[A-Za-z0-9_.-]+)?\z/;
} else {
    die "Invalid target (use one hostname or IPv4 address)\n"
        unless length($target) <= 253
        && $target =~ /\A(?:
              (?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}
              (?:25[0-5]|2[0-4]\d|[01]?\d?\d)
            | [A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
              (?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*
            )\z/x;
}

die "Timeout must be between 0.1 and 30 seconds\n"
    unless $timeout >= 0.1 && $timeout <= 30;
die "Concurrency must be between 1 and 1000\n"
    unless $conc >= 1 && $conc <= 1000;

my %selected;
for my $part (split /,/, $ports, -1) {
    $part =~ s/\A\s+|\s+\z//g;
    next if $part eq '';
    my ($a, $b);
    if ($part =~ /\A(\d{1,5})\z/) {
        ($a, $b) = ($1 + 0, $1 + 0);
    } elsif ($part =~ /\A(\d{1,5})-(\d{1,5})\z/) {
        ($a, $b) = ($1 + 0, $2 + 0);
    } else {
        die "Invalid port specification: $part\n";
    }
    die "Invalid port range: $part (ports must be 1-65535, low<=high)\n"
        unless $a >= 1 && $b <= 65535 && $a <= $b;
    $selected{$_} = 1 for $a .. $b;
}
my @ports = sort { $a <=> $b } keys %selected;
die "No ports selected\n" unless @ports;

# --- resolve once, up front -------------------------------------------------
my ($gerr, @res) = getaddrinfo(
    $literal // $target, undef, { socktype => SOCK_STREAM },
);
die "Cannot resolve '$target': $gerr\n" if $gerr;
die "Cannot resolve '$target' (no usable address)\n" unless @res;

# Keep the first address family we can actually open a socket on.
my ($family, $saddr, $numeric);
for my $r (@res) {
    my $probe;
    next unless socket($probe, $r->{family}, SOCK_STREAM, 0);
    close $probe;
    ($family, $saddr) = ($r->{family}, $r->{addr});
    my ($nerr, $num) = getnameinfo($r->{addr}, NI_NUMERICHOST);
    $numeric = $nerr ? $target : $num;
    last;
}
die "Cannot open a socket for '$target'\n" unless defined $family;

print "Only scan hosts you own or are authorized to test.\n";

if (!$yes) {
    my $answer;
    if (-t STDIN) {
        print "Confirm authorization [y/N]: ";
        $answer = <STDIN>;
    } else {
        $answer = <STDIN>;
    }
    $answer = '' unless defined $answer;
    chomp $answer;
    $answer =~ s/\A\s+|\s+\z//g;
    if ($answer !~ /\Ay(es)?\z/i) {
        if (!-t STDIN) {
            print STDERR "No TTY: pass -y/--yes (or pipe 'y') to confirm.\n";
            exit 2;
        }
        print "Cancelled.\n";
        exit 0;
    }
}

if (length $output && -e $output && !$yes) {
    print "Overwrite '$output'? [y/N]: ";
    my $a = <STDIN>;
    $a = '' unless defined $a;
    chomp $a;
    $a =~ s/\A\s+|\s+\z//g;
    die "Aborted; report not written.\n" unless $a =~ /\Ay(es)?\z/i;
}

my %SVC = (
    20 => 'ftp-data', 21 => 'ftp', 22 => 'ssh', 23 => 'telnet',
    25 => 'smtp', 53 => 'domain', 80 => 'http', 110 => 'pop3',
    111 => 'rpcbind', 123 => 'ntp', 135 => 'msrpc', 139 => 'netbios-ssn',
    143 => 'imap', 161 => 'snmp', 389 => 'ldap', 443 => 'https',
    445 => 'microsoft-ds', 465 => 'smtps', 514 => 'syslog', 587 => 'submission',
    636 => 'ldaps', 993 => 'imaps', 995 => 'pop3s', 1080 => 'socks',
    1433 => 'ms-sql-s', 1521 => 'oracle', 2049 => 'nfs', 2375 => 'docker',
    3306 => 'mysql', 3389 => 'ms-wbt-server', 5432 => 'postgresql',
    5900 => 'vnc', 6379 => 'redis', 8000 => 'http-alt', 8080 => 'http-proxy',
    8443 => 'https-alt', 9000 => 'cslistener', 9200 => 'elasticsearch',
    27017 => 'mongodb',
);
sub service {
    my $p = shift;
    return $SVC{$p} if exists $SVC{$p};
    # getservbyport() wants the port in network byte order; pack('n') gives that
    # without depending on Socket exporting htons().
    my $s = eval { getservbyport(pack('n', $p), 'tcp') };
    return $s if defined $s && length $s;
    return 'unknown';
}

my $open = 0;
my $closed = 0;
my $filtered = 0;
my $error = 0;
my $started = time();
my $done = 0;
my $total = scalar @ports;
my $interrupted = 0;
my $sockfail = 0;
my @results;

# Live concurrency cap. Starts at -c and backs off if the kernel refuses
# sockets, then creeps back up as the backlog drains.
my $eff = $conc;

sub record {
    my ($port, $label, $ref) = @_;
    $$ref++;
    push @results, [$port, $label];
    $done++;
    if (-t STDERR && $done % 250 == 0 && $done < $total) {
        print STDERR "\r  scanned $done/$total";
    }
}

$SIG{INT} = sub { $interrupted = 1 };

my @queue = @ports;
my %pend;
my $sel = IO::Select->new;

# Shortest pending deadline, but never longer than the timeout.
sub nap {
    my $w = $timeout;
    for my $e (values %pend) {
        my $d = $e->{deadline} - time;
        $w = $d if $d < $w;
    }
    $w = 0.005 if $w < 0.005;
    return $w;
}

while ((@queue || $sel->count) && !$interrupted) {
    # Creep the cap back toward -c once there is room again.
    $eff++ if $eff < $conc && $sel->count < $eff;

    # Fill up to the live cap.
    while (@queue && $sel->count < $eff) {
        my $port = shift @queue;
        my $s;
        unless (socket($s, $family, SOCK_STREAM, 0)) {
            # Kernel is out of descriptors: squeeze the cap to what is actually
            # in flight, put the port back, and try again next pass. Give up
            # rather than livelock if it never recovers.
            if (++$sockfail > 200) {
                die "Cannot open sockets (raise ulimit -n or lower -c)\n";
            }
            $eff = $sel->count > 1 ? $sel->count : 1;
            unshift @queue, $port;
            sleep 0.05;
            last;
        }
        $sockfail = 0;
        my $flags = fcntl($s, F_GETFL, 0) // 0;
        fcntl($s, F_SETFL, $flags | O_NONBLOCK);
        my $rc = connect($s, $saddr);
        if (!$rc && $!{EINPROGRESS}) {
            $sel->add($s);
            $pend{fileno $s} = {
                s        => $s,
                port     => $port,
                deadline => time + $timeout,
            };
        } elsif ($rc) {
            close $s;
            record($port, 'open', \$open);
        } else {
            my $e = $!;
            close $s;
            if ($e == ECONNREFUSED()) {
                record($port, 'closed', \$closed);
            } elsif ($e == EHOSTUNREACH() || $e == ENETUNREACH()) {
                record($port, 'error', \$error);
            } else {
                record($port, 'filtered', \$filtered);
            }
        }
    }

    # Drain whatever completed.
    for my $h ($sel->can_write(nap())) {
        my $e = $pend{fileno $h} or next;
        $sel->remove($h);
        delete $pend{fileno $h};
        my $err = 0;
        my $packed = getsockopt($h, SOL_SOCKET, SO_ERROR);
        $err = unpack('i', $packed) if defined $packed;
        close $h;
        if ($err == 0) {
            record($e->{port}, 'open', \$open);
        } elsif ($err == ECONNREFUSED()) {
            record($e->{port}, 'closed', \$closed);
        } elsif ($err == EHOSTUNREACH() || $err == ENETUNREACH()) {
            record($e->{port}, 'error', \$error);
        } else {
            record($e->{port}, 'filtered', \$filtered);
        }
    }

    # Sweep expired pending connects.
    my $now = time;
    for my $k (keys %pend) {
        next unless $pend{$k}{deadline} <= $now;
        my $e = delete $pend{$k};
        $sel->remove($e->{s});
        close $e->{s};
        record($e->{port}, 'filtered', \$filtered);
    }
}

if ($interrupted) {
    close $_->{s} for values %pend;
    print STDERR "\nInterrupted after $done port(s).\n";
} elsif (-t STDERR) {
    print STDERR "\r" . (' ' x 30) . "\r";
}

my $elapsed = time - $started;

# Sorted report; results were collected as they landed.
my @lines = (
    $NAME,
    "Target: $target ($numeric)",
    "PORT        STATE      SERVICE",
);
for my $r (sort { $a->[0] <=> $b->[0] } @results) {
    push @lines, sprintf('%-11s %-10s %s', "$r->[0]/tcp", $r->[1], service($r->[0]));
}
push @lines, sprintf(
    'Open: %d | Closed: %d | Filtered: %d | Error: %d | Scanned: %d/%d | Elapsed: %.2fs',
    $open, $closed, $filtered, $error, $done, $total, $elapsed,
);

print join("\n", @lines), "\n";

if (length $output) {
    open my $fh, '>', $output or die "Cannot write report '$output': $!\n";
    print {$fh} join("\n", @lines), "\n";
    close $fh or die "Cannot close report '$output': $!\n";
    print "Report saved: $output\n";
}

exit($interrupted ? 130 : 0);