#!/usr/bin/perl -w

use strict;
use CGI;

my $TTL_A  = 30;
my $TTL_MX = 30;

my $q = new CGI;

my ( $ip, $host, $password, $date );

# Si le script est utilis� sans les bons param�tres, on fait comme si on n'�tait pas l
$ip = $q->param('ip');
if ($ip =~ /^192\.168\./ || $ip =~ /^10\./ || $ip =~ /^172\.16/ || $ip =~ /^172\.31/ || $ip =~ /^127\.0\.0\./) {
    $ip = $q->remote_host();
}
$host = $q->param('host');
$password = $q->param('password');
#unless ( $ip = $q->param('ip') && $host = $q->param('host') && $password =
#  $q->param('password') )
unless ($ip && $host && $password) 
{
    print $q->header( -type => "text/html", -status => "404 Not Found" );
    exit 0;
}
# ddns faisait une diff�rence entre les records MX et A. Par d�faut, on fait un record A.
my $record = $q->param('record');
unless ($record) {
    $record = 'A';
}
my @records = split /:/, $record;

# On check si le password est le bon. S'il ne l'est pas, on fait un 404. (gnac gnac gnac...)
open PASSWD, "/etc/dyndns/passwd" or die;
my @passwd = <PASSWD>;
my $auth   = 0;
PASSWORD: foreach my $line (@passwd) {
    chomp($line);
    if ( $line =~ /^\Q$host\E:/ ) {
        if ( $password eq ( split /:/, $line )[1] ) {
            $auth = 1;
            last PASSWORD;
        }
    }
}
close PASSWD or die;

$date = `date +"%Y/%m/%d %H:%M:%S"`;
chomp($date);
open(LOG,">>/var/log/dyndns.log");
if ( $auth == 0 ) {
    print $q->header( -type => "text/html", -status => "404 Not Found" );
    print LOG "$date\t$ip\t$host\t404 Bad password\n";
    close(LOG);
    exit 0;
}
print LOG "$date\t$ip\t$host\n";
close(LOG);

# Bon. Le client est authentifi�, on peut faire la vraie job.
foreach my $record (@records) {
    open NSUPDATE, ">/var/named/dyndns/.$host.nsupdate" or die $!;
    if ( $record =~ /^A$/i ) {
        print NSUPDATE
"prereq yxrrset $host. IN A\nupdate delete $host. IN A\nupdate add $host. $TTL_A IN A $ip\n\nprereq nxrrset $host. IN A\nupdate add $host. $TTL_A IN A $ip\n\n";
        close NSUPDATE or die;
        system "/usr/bin/nsupdate /var/named/dyndns/.$host.nsupdate";
    }
    elsif ( $record =~ /^MX$/i ) {
        print NSUPDATE
"prereq yxrrset $host. IN MX\nupdate delete $host. IN MX\nupdate add $host. $TTL_MX IN MX 10 garcon.$host\n\nprereq nxrrset $host. IN MX\nupdate add $host. $TTL_MX IN MX 10 garcon.$host\n\n";
        close NSUPDATE;
        system "/usr/bin/nsupdate /var/named/dyndns/.$host.nsupdate" and die;
    }
    #rename "/var/named/.dyndns/$host", "/var/named/.dyndns/.clients/$host"
    #  or die;
    #system "mv /var/named/.dyndns/$host /var/named/.dyndns/.clients/$host";
    rename "/var/named/dyndns/.$host.nsupdate", "/var/named/dyndns/$host.nsupdate" or die;
}

print $q->header('text/html');
print $q->start_html( -title => 'OK' );
print $q->end_html;


