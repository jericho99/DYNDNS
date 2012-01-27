# $Id: Sysadmin.pm 2300 2006-03-13 21:36:59Z chuck $

use strict;

package Sysadmin;

use DBI;
use Errno;
use Exporter;
use POSIX;

our @ISA    = qw(Exporter);
our @EXPORT =
  qw(&sudo &sudo_pipe &untaint_dir_if_looks_safe &untaint_file_if_looks_safe &safe_backticks &safe_pipe &parseRC &storeRC &parseRC_string &contains);

our $VERSION = "0.01";
sub Version { $VERSION }
use 5.6.0;

=head1 FONCTIONS DIVERSES

=head2 sudo

Cette fonction doit être callée à la place de B<sudo> lui-même, lorsque
possible. Elle sert à deux choses:

=over 4

=item 1.

S'assurer que le call à B<sudo> bypass le shell.

=item 2.

On peut setter une variable dans le fichier de config qui fait que l'interface
va agir en mode démo et va afficher un message d'erreur lorsqu'un call à sudo()
est fait.

=back

sudo() accepte X arguments, qui seront passés à B<sudo>.

=cut

sub sudo {
    return sudo_pipe( undef, @_ );
}

sub sudo_pipe {
    my $stdin = shift @_;

#    my $demo_mode = Sysadmin::Config->new->get( 'Libexec', 'Demo', 0 );

    # Il faut changer $call_if_demo dépendant de l'interface
#    my $call_if_demo = "Marcel::demo_mode";

 #   if ($demo_mode) {
  #      no strict 'refs';
   #     &$call_if_demo;
    #    return;
    #}

    pipe IN_READ,  IN_WRITE;
    pipe OUT_READ, OUT_WRITE;
    my $pid;
  FORK: {
        if ( $pid = fork ) {

            # fall through
        }
        elsif ( defined $pid ) {
            sudo_child(@_);
        }
        elsif ( $! == Errno::EAGAIN ) {
            sleep 5;
            redo FORK;
        }
        else {
            die "Can't fork: $!\n";
        }
    }

    close IN_READ;
    close OUT_WRITE;
    print IN_WRITE $stdin;
    close IN_WRITE;
    my @output = <OUT_READ>;
    close OUT_READ;
    waitpid $pid, 0;
    my $retval = $? >> 8;

    if ( $retval != 0 ) {
        my $command = join ' ', @_;
        die <<EOF;
error running sudo:
    command = $command
    stdin = $stdin
    retval = $retval
@output
EOF
    }
    return wantarray ? @output : join "", @output;
}
=head2 untaint_dir_if_looks_safe( FILEHANDLE )

Pour enlever le taint d'un dirhandle, on call cette fonction
avec le dirhandle et le nom du directory en argument. Elle fait deux checks:

=over 4

=item 1.

Le owner peut seulement être root.

=item 2.

Groupe et Autre n'ont pas droit d'écrire dans le répertoire.

=back

=cut

use Symbol 'qualify_to_ref';
use IO::Handle;

sub untaint_dir_if_looks_safe(*$) {
    my $fh   = qualify_to_ref( shift, caller );
    my @info = stat shift;

    if ( $info[4] == 0 and not $info[2] & 022 ) {
        IO::Handle::untaint($fh);
    }
}

=head2 untaint_file_if_looks_safe( FILEHANDLE )

Pour enlever le taint d'un filehandle, on call cette fonction avec le filehandle
en argument. Elle fait deux checks:

=over 4

=item 1.

Le owner peut seulement être root ou moi-même.

=item 2.

Groupe et Autre n'ont pas droit d'écriture.

=back

=cut

use File::stat;
use Symbol 'qualify_to_ref';
use IO::Handle;

sub untaint_file_if_looks_safe(*) {
    my $fh = qualify_to_ref( shift, caller );
    my $info = stat($fh);
    return unless $info;

    if ( $info->uid != 0 && $info->uid != $< ) {

        #                return 0;   ## Va falloir décommenter ça dans
        #                            ## la version de production
    }

    if ( $info->mode & 022 ) {

        #                return 0;   ## Idem
    }

    IO::Handle::untaint($fh);
}

=head2 safe_backticks( @COMMANDE )

Cette fonction est comme des backticks, sauf que ça n'utilise pas le shell. Plus sécuritaire.

=cut

sub safe_backticks {
    local %ENV;
    defined( my $pid = open FROM_CHILD, '-|' ) or die "can't fork: $!";
    if ($pid) {
        my @output = <FROM_CHILD>;
        close FROM_CHILD;
		# Sometimes the " close " will produce a "No child process" error
		# This is a workaround this problem. It shouldn't report an error
		# upon closing the FROM_CHILD filehandle but it does once in a while.
        my $retval = $? >> 8;
        if ( $retval != 0 and $! ne "No child processes" ) {
            my $command = join ' ', @_;
            die <<EOF;
error running safe_backticks:
    command = $command
	pid     = $pid
    retval  = $retval
	\$!      = $!
@output
EOF
        }
        return wantarray ? @output : join "", @output;
    }
    else {
        $ENV{LC_MESSAGES} = "en_US";
        open STDERR, ">&STDOUT" or die "Can't dup STDOUT";
        exec @_ or die "can't exec: $!";
    }
}

=head2 safe_pipe( $WHAT_TO_PIPE, @COMMANDE )

Cette fonction est à peu près l'inverse de safe_backticks.

=cut

sub safe_pipe {
    my $to_pipe = shift;
    defined( my $pid = open TO_CHILD, '|-' ) or die "can't fork: $!";
    if ($pid) {
        print TO_CHILD $to_pipe;
        close TO_CHILD;
        return 1;
    }
    else {
        exec @_ or die "can't exec: $!";
    }
}

=head2 parseRC( $FILE )

DEPRECATED: Use Sysadmin::Config or Config::IniFiles instead.

parseRC() lit un fichier de format utilisé par les programmes de KDE. Par exemple:

    clé = valeur
    ... = ...
    
    [groupe1]
    clé = valeur
    bla = bla

    [groupe2]
    blah = blah

On retourne une référence à une structure de données qui, dans le cas précédent, ressemblerait à ceci:

    $VAR1 = {
        general => {
            clé => 'valeur',
        },
        groups => {
            groupe1 => {
                clé => 'valeur',
                bla => 'bla',
            },
            groupe2 => {
                blah => 'blah',
            },
        },
    };

=cut

sub parseRC {
    my $file = shift;

    my %rc;
    my $group = undef;
    open RC, $file or die "Can't open $file for reading: $!\n";
    while (<RC>) {
        next if /^\s*#/ or /^\s*$/ or /^\s*;/;
        s/\s+#.*//;
        if (/^\s*\[\s*(.+?)\s*\]\s*$/) {
            $group = $1;
            next;
        }
        elsif (/^\s*([^=]+?)\s*=\s*(.*)$/) {
            my $key = lc $1;
            $key =~ s/\s{2,}/ /g;
            my $value = $2;
            if ( $value =~ /<<(\S+)/ ) {
                my $end_delimiter = $1;
                $value = '';
                while (<RC>) {
                    last if /^\Q$end_delimiter\E$/;
                    $value .= $_;
                }
            }
            if ( defined $group ) {
                $rc{groups}{$group}{$key} = $value;
            }
            else {
                $rc{general}{$key} = $value;
            }
        }
    }
    return \%rc;
}

sub parseRC_string {
    my $rc = shift;

    my @rc = split /^/m, $rc;
    my %rc;
    my $group = undef;
    while ( $_ = shift @rc ) {
        next if /^\s*#/ or /^\s*$/ or /^\s*;/;
        s/\s+#.*//;
        if (/^\s*\[\s*(.+?)\s*\]\s*$/) {
            $group = $1;
            next;
        }
        elsif (/^\s*([^=]+?)\s*=\s*(.*)$/) {
            my $key = lc $1;
            $key =~ s/\s{2,}/ /g;
            my $value = $2;
            if ( $value =~ /<<(\S+)/ ) {
                my $end_delimiter = $1;
                $value = '';
                while ( $_ = shift @rc ) {
                    last if /^\Q$end_delimiter\E$/;
                    $value .= $_;
                }
            }
            if ( defined $group ) {
                $rc{groups}{$group}{$key} = $value;
            }
            else {
                $rc{general}{$key} = $value;
            }
        }
    }
    return \%rc;
}

=head2 storeRC( $STRUCT_REF, $FILE )

DEPRECATED: Use Sysadmin::Config or Config::IniFiles instead.

$STRUCT_REF est une référence à une structure de données au format décrit dans la fonction parseRC(). $FILE est un fichier où sera écrite la configuration. Le contenu de $FILE sera effacé.

=cut

sub storeRC {
    my $rc_ref = shift;
    my $file   = shift;

    open RC, '>', $file or die "Can't open $file for writing: $!\n";

    my $longest;
    foreach ( keys %{ $rc_ref->{general} } ) {
        my $length = length $_;
        $longest = $length if $length > $longest;
    }
    foreach my $group ( sort keys %{ $rc_ref->{groups} } ) {
        foreach ( keys %{ $rc_ref->{groups}{$group} } ) {
            my $length = length $_;
            $longest = $length if $length > $longest;
        }
    }

    if ( %{ $rc_ref->{general} } ) {
        foreach ( sort keys %{ $rc_ref->{general} } ) {
            print RC $_
              . ( ' ' x ( $longest - length($_) + 1 ) )
              . "= $rc_ref->{general}{$_}\n"
              if $rc_ref->{general}{$_} !~ /^\s*$/;
        }
        print RC "\n";
    }

    foreach my $group ( sort keys %{ $rc_ref->{groups} } ) {
        print RC "[$group]\n";
        print RC "printing"
          . ( ' ' x ( $longest - length("printing") + 1 ) ) . "= "
          . $rc_ref->{groups}{$group}{printing} . "\n"
          if ( defined $rc_ref->{groups}{$group}{printing} );
        foreach ( sort keys %{ $rc_ref->{groups}{$group} } ) {
            next if ( $_ eq "printing" );
            print RC $_
              . ( ' ' x ( $longest - length($_) + 1 ) )
              . "= $rc_ref->{groups}{$group}{$_}\n"
              if $rc_ref->{groups}{$group}{$_} !~ /^\s*$/;
        }
        print RC "\n";
    }

    close RC;
}

=item daemon()

This is the equivalent of the C daemon(3) function.

=cut

sub daemon {
    my ( $nochdir, $noclose ) = @_;

    if ( my $pid = fork ) {
        POSIX::_exit(0);
    }
    elsif ( not defined $pid ) {
        die "Couldn't fork: $!";
    }

    if ( POSIX::setsid() == -1 ) {
        die 'setsid() failed';
    }

    unless ($nochdir) {
        chdir '/' or die "Couldn't chdir to /: $!";
    }

    unless ($noclose) {
        open NULLFH, '+</dev/null' or die "Can't open /dev/null: $!";
        open STDIN,  '<&', 'NULLFH'    or die "Can't redirect STDIN: $!";
        open STDOUT, '>&', 'NULLFH'    or die "Can't redirect STDOUT: $!";
        open STDERR, '>&', 'NULLFH'    or die "Can't redirect STDERR: $!";
    }
}

=item contains( ARRAY, ARRAY )

Utility function. Returns true if the first array completely contains the
second array..

=cut

sub contains (\@@) {
    my ( $container, @contained );

    # If we're checking for a single item, do a simple loop. O(n).
    if ( @contained == 1 ) {
        my $contained = shift @contained;
        foreach (@$container) {
            return 1 if $_ eq $contained;
        }
        return 0;
    }

    # Otherwise, use a hash so that we don't do multiple loops. Probably
    # something like O(n*log(n)).
    else {
        my %container_hash = map { $_ => 1 } @$container;
        foreach (@contained) {
            return 0 if not exists $container_hash{$_};
        }
        return 1;
    }
}

1;
