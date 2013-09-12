use Irssi;
use vars qw/$VERSION %IRSSI/;
use File::Spec;
use DBI;
use POSIX qw/ strftime /;

# Requires:
#   DBI
#   DBD::SQLite

$VERSION = '0.76';
%IRSSI = (
    authors     => 'SymKat',
    contact     => 'symkat@symkat.com',
    name        => "stalker",
    description => 'Records and correlates nick!user@host information',
    license     => "BSD",
    url         => "http://github.com/symkat/stalker",
    changed     => "2012-11-05",
    changes     => "See Change Log",
);

# Bindings
Irssi::signal_add_last( 'event 311', \&whois_request );
Irssi::signal_add( 'message join', \&nick_joined );
Irssi::signal_add( 'nicklist changed', \&nick_changed_channel );
Irssi::signal_add( 'channel sync', \&channel_sync );
Irssi::signal_add( 'pidwait', \&record_added );

Irssi::command_bind( 'host_lookup', \&host_request );
Irssi::command_bind( 'nick_lookup', \&nick_request );
Irssi::command_bind( 'nick_lookup_h', \&nick_request_hosts );

Irssi::theme_register([
    $IRSSI{'name'} => '{whois stalker %|$1}',
    $IRSSI{'name'} . '_join' => '{channick_hilight $0} {chanhost_hilight $1} has joined '
        . '{hilight $2} ({channel $3})', 
]);

# Settings
Irssi::settings_add_str( 'Stalker',  $IRSSI{name} . "_db_path", "nicks.db" );
Irssi::settings_add_str( 'Stalker',  $IRSSI{name} . "_max_recursion", 20 );
Irssi::settings_add_str( 'Stalker',  $IRSSI{name} . "_guest_nick_regex", "^guest" );
Irssi::settings_add_str( 'Stalker',  $IRSSI{name} . "_guest_host_regex", "^webchat" );
Irssi::settings_add_str( 'Stalker',  $IRSSI{name} . "_debug_log_file", "stalker.log" );

Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_verbose", 0 );
Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_debug", 0 );
Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_recursive_search", 1 );
Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_search_this_network_only", 0 );
Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_ignore_guest_nicks", 1 );
Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_ignore_guest_hosts", 0 );
Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_debug_log", 0 );
Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_stalk_on_join", 0 );
Irssi::settings_add_bool( 'Stalker', $IRSSI{name} . "_normalize_nicks", 1 );

my $count;
my %data;
my $str;

# Database

my $db = Irssi::settings_get_str($IRSSI{name} . '_db_path');
if ( ! File::Spec->file_name_is_absolute($db) ) {
    $db = File::Spec->catfile( Irssi::get_irssi_dir(), $db );
}

stat_database( $db );

my $DBH = DBI->connect(
    'dbi:SQLite:dbname='.$db, "", "",
    {
        RaiseError => 1,
        AutoCommit => 1,
    }
) or die "Failed to connect to database $db: " . $DBI::errstr;

# DBI::SQLite and fork() don't mix. Do it anyhow but keep the parent and child DBH separate?
# Ideally the child should open its own connection.
my $DBH_child = DBI->connect(
    'dbi:SQLite:dbname='.$db, "", "",
    {
        RaiseError => 1,
        AutoCommit => 1,
    }
) or die "Failed to connect to database $db: " . $DBI::errstr;

# async data
my @records_to_add; # Queue of records to add
my $child_running = 0;   # child pid that is running

# IRSSI Routines

sub whois_request {
    my ( $server, $data, $server_name ) = @_;
    my ( $me, $n, $u, $h ) = split(" ", $data );
   
    $server->printformat($n,MSGLEVEL_CRAP,$IRSSI{'name'},$n, 
        join( ", ", (get_nick_records('host', $h, $server->{address}))) . "." );
}

sub nick_request_hosts {
	my ( $query, $server ) = ( $_[0], $_[1]->{address} )
	$query =~ s/ $//;
    windowPrint( join( ", ", (get_host_records('nick', $query, $server))) . ".");
}

sub host_request {
	my ( $query, $server ) = ( $_[0], $_[1]->{address} )
	$query =~ s/ $//;
    windowPrint( join( ", ", (get_nick_records('host', $query, $server))) . ".");
}

sub nick_request {
	my ( $query, $server ) = ( $_[0], $_[1]->{address} )
	$query =~ s/ $//;
    windowPrint( join( ", ", (get_nick_records('nick', $query, $server))) . ".");
}

#   Record Adding Functions
sub nick_joined {
    my ( $server, $channel, $nick, $address ) = @_;
    my ( $user, $host ) = ( split ( '@', $address, 2 ) );

    add_record( $nick, $user, $host, $server->{address});
    
    if ( Irssi::settings_get_bool($IRSSI{name} . "_stalk_on_join") ) {
        my $window = $server->channel_find($channel);
        my @used_nicknames = get_nick_records( 'host', $host, $server->{address} );
        
        $window->printformat( MSGLEVEL_JOINS, 'stalker_join', 
            $nick, $address, $channel, join( ", ", @used_nicknames )); 
        Irssi::signal_stop(); 
    }
}

sub nick_changed_channel {
    add_record( $_[1]->{nick}, (split( '@', $_[1]->{host} )), $_[0]->{server}->{address} );
}

sub channel_sync {
    my ( $channel ) = @_;
    
    my $serv = $channel->{server}->{address};

    for my $nick ( $channel->nicks() ) {
        last if $nick->{host} eq ''; # Sometimes channel sync doesn't give us this...
        add_record( $nick->{nick}, ( split( '@', $nick->{host} ) ), $serv );
    }
}


# Automatic Database Creation And Checking
sub stat_database {
    my ( $db_file ) = @_;
    my $do = 0;

    debugPrint("info", "Stat database.");
    if ( ! -e $db_file  ) {
        open my $fh, '>', $db_file
            or die "Cannot create database file.  Abort.";
        close $fh;
        $do = 1;
    }
    my $DBH = DBI->connect(
        'dbi:SQLite:dbname='.$db_file, "", "",
        {
            RaiseError => 1,
            AutoCommit => 1,
        }
    );

    create_database( $DBH ) if $do;

    my $sth = $DBH->prepare( "SELECT nick from records WHERE serv = ?" );
    $sth->execute( 'script-test-string' );
    my $sane = $sth->fetchrow_array;
    
    create_database( $DBH ) if $sane == undef;

    # Magical testing for the new "added" column; this column was added later
    # Need to test for its existance and "add" it if missing
    $sth = $DBH->prepare( "SELECT * FROM records WHERE serv = ?;" );
    $sth->execute( 'script-test-string' );
    my @arr = $sth->fetchrow_array; # I can't convert to a row count without storing in an array first
    if( scalar(@arr) == 4 ) { # 4 columns is the old format
        debugPrint("info", "Add timestamp column to existing database.");
        add_timestamp_column($DBH);
    }
    elsif( scalar(@arr) != 5 ) { # 5 is the new. Anything else is ... wrong
        die "The DB should have 4 or 5 columns. Found " . scalar(@arr);
    }

    index_db( $DBH );
}

# Add indices to the DB. If they already exist, no harm done. 
# Is there an easy way to test if they exist already?
sub index_db {
    my ( $DBH ) = @_;

    my @queries = ( 
        "CREATE INDEX index1 ON records (nick)",
        "CREATE INDEX index2 ON records (host)",
    );
    $DBH->{RaiseError} = 0;
    $DBH->{PrintError} = 0;
    for my $query (@queries) {
        $DBH->do( $query );
    }
    $DBH->{RaiseError} = 1;
    $DBH->{PrintError} = 1;
}


# Create a new table with the extra column, move the data over. delete old table and alter name
sub add_timestamp_column {
    my ( $DBH ) = @_;

    Irssi::print("Adding a timestamp column to the nicks db. Please wait...");

    # Save the old records
    $DBH->do( "ALTER TABLE records RENAME TO old_records" );

    # Create the new table
    create_database( $DBH );

    # Copy the old records over and drop them
    my @queries = (
        "INSERT INTO records (nick,user,host,serv) SELECT nick,user,host,serv FROM old_records",
        "DROP TABLE old_records",
    );
    for my $query (@queries) {
        my $sth = $DBH->prepare($query) or die "Failed to prepare '$query'. " . $sth->err;
        $sth->execute() or die "Failed to execute '$query'. " . $sth->err;
    }
}

sub create_database {
    my ( $DBH ) = @_;
    
    my @queries = ( 
        "DROP TABLE IF EXISTS records",
        "CREATE TABLE records (nick TEXT NOT NULL," .
            "user TEXT NOT NULL, host TEXT NOT NULL, serv TEXT NOT NULL, " .
            "added DATE NOT NULL DEFAULT CURRENT_TIMESTAMP)",
        "INSERT INTO records (nick, user, host, serv) VALUES( 1, 1, 1, 'script-test-string' )"
    );
    
    # Drop table is exists
    # Create the table and indices
    # Insert test record
    for my $query (@queries) {
        my $sth = $DBH->prepare($query) or die "Failed to prepare '$query'. " . $sth->err;
        $sth->execute() or die "Failed to execute '$query'. " . $sth->err;
    }
    index_db( $DBH );
}

# Other Routines

# Strip certain chars from the nick if the nick exists without them 
sub normalize {
    my ( @nicks ) = @_;
    my ( %nicks, %ret ) = map { $_, 1 } @nicks;

    for my $nick ( @nicks ) {
        (my $base = $nick ) =~ s/[\Q-_~^`\E]//g;
        $ret{ exists $nicks{$base} ? $base : $nick }++;
    }
    return keys %ret;
}

sub add_record {
    my ( $nick, $user, $host, $serv ) = @_;
    return unless ($nick and $user and $host and $serv);
    
    # Queue the record data and run child unless it's already forked
    debugPrint("info", "Queue record to add to DB and, if needed, start child process.");
    push @records_to_add, [$nick, $user, $host, $serv];
    async_add() if (not $child_running);
}

# Signalled by pidwait -> child exited -> set child not running and fork() again if items are queued
sub record_added
{
    $child_running = 0;
    debugPrint("info", "Child process complete. Make new child if needed.");
    async_add() if (@records_to_add);
}

# Grab the queue and fork a child to process it
# Signal parent when child is done so we know when it's safe to fork() again
sub async_add
{
    return unless (@records_to_add);
    # Copy the queue of records
    my @record_list = @records_to_add;

    my $pid = fork();
    if (not defined $pid)
    {
        debugPrint( "crit", "Failed to fork()" );
        return;
    }

    # The child is working.
    # Parent uses this to prevent fork()ing until child finishes. 
    # Child uses this to prevent doing things that only the parent should do.
    $child_running = $pid;

    if ($pid > 0) # parent thread
    {
        @records_to_add = (); # Reset the queue
        Irssi::pidwait_add($pid); # Signal when child is done
        return;
    }

    # First thing is to unregister signals. That might prevent the child from catching whatever is causing Issue #3
    Irssi::signal_remove( 'event 311', \&whois_request );
    Irssi::signal_remove( 'message join', \&nick_joined );
    Irssi::signal_remove( 'nicklist changed', \&nick_changed_channel );
    Irssi::signal_remove( 'channel sync', \&channel_sync );
    Irssi::signal_remove( 'pidwait', \&record_added );
    Irssi::command_unbind( 'host_lookup', \&host_request );
    Irssi::command_unbind( 'nick_lookup', \&nick_request );
    Irssi::command_unbind( 'nick_lookup_h', \&nick_request_h );

    # In child, do the database tasks
    db_add_record(@{$_}) for (@record_list);
    # When done, exit which signals the parent
    POSIX::_exit(1);
}

sub db_add_record
{
    my ($nick, $user, $host, $serv) = @_;

    # Check if we already have this record.
    my $q = "SELECT nick FROM records WHERE nick = ? AND user = ? AND host = ? AND serv = ?";
    my $sth = $DBH_child->prepare( $q );
    $sth->execute( $nick, $user, $host, $serv );
    my $result = $sth->fetchrow_hashref;

    if ( $result->{nick} eq $nick ) {
        #debugPrint( "info", "Record for $nick skipped - already exists." );
        return 1;
    }

    debugPrint( "info", "Adding to DB: nick = $nick, user = $user, host = $host, serv = $serv" );

    # We don't have the record, add it.
    $sth = $DBH_child->prepare
        ("INSERT INTO records (nick,user,host,serv) VALUES( ?, ?, ?, ? )" );
    eval { $sth->execute( $nick, $user, $host, $serv ) };
    if ($@) {
        debugPrint( "crit", "Failed to process record, database said: $@" );
    }

    debugPrint( "info", "Added record for $nick!$user\@$host to $serv" );
}

sub get_host_records {
    my ( $type, $query, $serv, @return ) = @_;

    $count = 0; %data = (  );
    my %data = _r_search( $serv, $type, $query );
    for my $k ( keys %data ) {
        debugPrint( "info", "$type query for records on $query from server $serv returned: $k" );
        push @return, $k if $data{$k} eq 'host';
    }

    # case-insensitive sort
    return sort {uc($a) cmp uc($b)} @return;
}

sub get_nick_records {
    my ( $type, $query, $serv, @return ) = @_;

    $count = 0; %data = (  );
    my %data = _r_search( $serv, $type, $query );
    for my $k ( keys %data ) {
        debugPrint( "info", "$type query for records on $query from server $serv returned: $k" );
        push @return, $k if $data{$k} eq 'nick';
    }

    if ( Irssi::settings_get_bool($IRSSI{name} . "_normalize_nicks" ) ) {
        @return = normalize(@return);
    }

    # case-insensitive sort
    return sort {uc($a) cmp uc($b)} @return;
}

sub _r_search {
    my ( $serv, $type, @input ) = @_;
    return %data if $count > 1000;
    return %data if $count > Irssi::settings_get_str($IRSSI{name} . "_max_recursion");
    return %data if $count == 2 and ! Irssi::settings_get_bool( $IRSSI{name} . "_recursive_search" );

    debugPrint( "info", "Recursion Level: $count" );
    
    if ( $type eq 'nick' ) {
        $count++;
        for my $nick ( @input ) {
            next if exists $data{$nick};
            $data{$nick} = 'nick';
            my @hosts = _get_hosts_from_nick( $nick, $serv );
            _r_search( $serv, 'host', @hosts );
        }
    } elsif ( $type eq 'host' ) {
        $count++;
        for my $host ( @input ) {
            next if exists $data{$host};
            $data{$host} = 'host';
            my @nicks = _get_nicks_from_host( $host, $serv );
            verbosePrint( "Got nicks: " . join( ", ", @nicks ) . " from host $host" );
            _r_search( $serv, 'nick', @nicks );
        }
    }

    return %data;
}

sub _get_hosts_from_nick {
    my ( $nick, $serv, @return ) = @_;

    my $sth;
    if ( Irssi::settings_get_bool( $IRSSI{name} .  "_search_this_network_only" ) ){
        $sth = $DBH->prepare( "SELECT nick, host FROM records WHERE nick = ? AND serv = ?" );
        $sth->execute( $nick, $serv );
    } else {
        $sth = $DBH->prepare( "SELECT nick, host FROM records WHERE nick = ?" );
        $sth->execute( $nick );
    }

    return _ignore_guests( 'host', $sth );
}

sub _get_nicks_from_host {
    my ( $host, $serv, @return ) = @_;

    my $sth;
    if ( Irssi::settings_get_bool( $IRSSI{name} .  "_search_this_network_only" ) ){
        $sth = $DBH->prepare( "SELECT nick, host FROM records WHERE host = ? AND serv = ?" );
        $sth->execute( $host, $serv );
    } else {
        $sth = $DBH->prepare( "SELECT nick, host FROM records WHERE host = ?" );
        $sth->execute( $host );
    }

    return _ignore_guests( 'nick', $sth );
}

sub _ignore_guests {
    my ( $field, $sth ) = @_;
    my @return;

    while ( my $row = $sth->fetchrow_hashref ) {
        if ( Irssi::settings_get_bool($IRSSI{name} . "_ignore_guest_nicks") ) {
            my $regex = Irssi::settings_get_str( $IRSSI{name} . "_guest_nick_regex" );
            next if( $row->{nick} =~ m/$regex/i );
        }
        if ( Irssi::settings_get_bool($IRSSI{name} . "_ignore_guest_hosts") ) {
            my $regex = Irssi::settings_get_str( $IRSSI{name} . "_guest_host_regex" );
            next if( $row->{host} =~ m/$regex/i );
        }
        push @return, $row->{$field};
    }
    return @return;
}

# Handle printing.
sub debugPrint {
    # Short cut - instead of two debug statements thoughout the code,
    # we'll send all debugPrint's to the debugLog function as well

    windowPrint( $IRSSI{name} . " Debug: " . $_[1] )
        if Irssi::settings_get_bool($IRSSI{name} . "_debug");
    debugLog( $_[0], $_[1] );
}

sub verbosePrint {
    windowPrint( $IRSSI{name} . " Verbose: " . $_[0] )
        if Irssi::settings_get_bool($IRSSI{name} . "_verbose");
}

sub debugLog {
    my ( $lvl, $msg ) = @_;
    return unless Irssi::settings_get_bool($IRSSI{name} . "_debug_log" );
    my $now = strftime( "[%D %H:%M:%S]", localtime );

    my $logpath = Irssi::settings_get_str( $IRSSI{name} . "_debug_log_file" );
    if ( ! File::Spec->file_name_is_absolute($logpath) ) {
        $logpath = File::Spec->catfile( Irssi::get_irssi_dir(), $logpath );
    }

    open my $fh, ">>", $logpath
        or die "Fatal error: Cannot open my logfile at " . $IRSSI{name} . "_debug_log_file for writing: $!";
    print $fh "[$lvl] $now $msg\n";
    close $fh;
}

sub windowPrint {
    Irssi::active_win()->print( $_[0] );
}

windowPrint( "Loaded $IRSSI{'name'}" );

# Happy apt-get'ing, azizLIGHTS
