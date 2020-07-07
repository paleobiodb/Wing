package Wing::Session;

use Moose;
use Wing::Perl;
use Data::GUID;
use URI::Escape;
use Ouch;

no warnings 'experimental';

has db => (
    is          => 'ro',
    required    => 1,
);

has id => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        return Data::GUID->new->as_string;
    },
);

# Altered by Michael McClennen, 2020-07-06. If no session is found in the cache for a given
# session id but a record exists in the pbdb.session_data table, then create and store a new
# session record in the cache. This way, restarting the container in which this code is running
# will preserve login sessions. In order to make this work, the fields 'password_hash' and
# 'ip_address' were to be added to pbdb.session_data.

sub BUILD {
    my $self = shift;
    my $db = shift;
    my $session_id = $self->id;
    my $session_data = Wing->cache->get('session'.$session_id);
    if (defined $session_data && ref $session_data eq 'HASH') {
        $self->password_hash($session_data->{password_hash});
        $self->user_id($session_data->{user_id});
        $self->extended($session_data->{extended});
	$self->expire_days($session_data->{expire_days});
        $self->ip_address($session_data->{ip_address});
        $self->api_key_id($session_data->{api_key_id});
    }
    else
    {
	my $storage = Wing->db->storage;
	my ($user_id, $password_hash, $ip_address, $expire_days) = $storage->dbh_do(
	    sub {
		my ($storage, $dbh, $session_id) = @_;
		my $quoted = $dbh->quote($session_id);
		$dbh->selectrow_array("SELECT user_id, password_hash, ip_address, expire_days FROM pbdb.session_data
					WHERE session_id = $quoted");
	    }, $session_id);
	$self->user_id($user_id);
	$self->password_hash($password_hash);
	$self->ip_address($ip_address);
	$self->expire_days($expire_days);
	$self->extended(0);
	$self->api_key_id(Wing->config->get('default_api_key'));
    }
    return $session_data;
}

has extended => (
    is          => 'rw',
    default     => 0,
);

has expire_days => (
    is          => 'rw',
    default     => 1,
);

has api_key_id => (
    predicate   => 'has_api_key_id',
    is          => 'rw',
);

has ip_address => (
    is          => 'rw',
);

has sso => (
    is          => 'rw',
    default     => 0,
);

has user_id => (
    is          => 'rw',
    predicate   => 'has_user_id',
    trigger     => sub {
        my $self = shift;
        $self->clear_user;
    },
);

has password_hash => (
    is          => 'rw',
    predicate   => 'has_password_hash',
);

has user => (
    is          => 'rw',
    predicate   => 'has_user',
    clearer     => 'clear_user',
    lazy        => 1,
    default     => sub {
        my $self = shift;
        return undef unless $self->has_user_id;
        my $user = $self->db->resultset('User')->find($self->user_id);
        if (defined $user) {
            $user->current_session($self);
        }
        return $user;
    },
);

sub get_permissions {
    my $self = shift;
    my @permissions = $self->db->resultset('APIKeyPermission')->search({
        user_id     => $self->user_id,
        api_key_id  => $self->api_key_id,
    })
    ->get_column('permission')
    ->all;
    return \@permissions;
}

sub check_permissions {
    my ($self, $permissions) = @_;
    return 1 unless $self->sso; # always has permissions if this isn't a single-sign-on session
    return 1 if (!defined $permissions || ref $permissions ne 'ARRAY' || !scalar(@{$permissions})); # has permissions if they aren't asking for any
    ouch(401, 'You must log in to access that.',$permissions) unless $self->has_user_id; # can't have permissions if they haven't logged in
    return 1 if $self->user->is_admin; # always has permissions if they're an admin
    ouch(450, 'Insufficient permissions.',$permissions) unless $self->has_api_key_id; # can't have permissions if they didn't assign an API key
    my $existing = $self->get_permissions;
    foreach my $permission (@{$permissions}) {
        unless ($permission ~~ $existing) {
            ouch(450, 'Insufficient permissions.',$permissions);
        }
    }
    return 1;
}

sub extend {
    my $self = shift;
    if (!$self->user || $self->password_hash ne $self->user->password) {
        $self->end;
        return;
    }
    $self->extended( $self->extended + 1 );
    Wing->cache->set(
        'session'.$self->id,
        {
            password_hash    => $self->password_hash, # this hash is stored here so that if the user changes their password we can log out all existing sessions
            user_id     => $self->user_id,
            ip_address  => $self->ip_address,
	    expire_days => $self->expire_days,
	    extended    => $self->extended,
            api_key_id  => $self->api_key_id,
        },
        60 * 60 * 24 * 7,
    );
    return $self;
}

sub is_human {
    my $self = shift;
    if (Wing->cache->get($self->id.'_is_human')) {
        return 1;
    }
    ouch 455, 'Must verify humanity.';
}

sub end {
    my $self = shift;
    Wing->cache->remove('session'.$self->id);
    Wing->db->storage->dbh_do(
	    sub {
		my ($storage, $dbh, $session_id) = @_;
		my $quoted = $dbh->quote($session_id);
		$dbh->do("DELETE FROM pbdb.session_data	WHERE session_id = $quoted");
	    }, $self->id);
    return $self;
}

sub start {
    my ($self, $user, $options) = @_;
    $self->user_id($user->id);
    $self->password_hash($user->password);
    $user->current_session($self);
    $self->user($user);
    $self->ip_address($options->{ip_address});
    $self->expire_days($options->{expire_days} || 1);
    $self->api_key_id($options->{api_key_id});
    return $self->extend;
}

sub describe {
    my ($self, %options) = @_;
    my $out = {
        id          => $self->id,
        object_type => 'session',
        object_name => 'Session',
        user_id     => $self->user_id,
    };
    if ($options{include_private} || (exists $options{current_user} && defined $options{current_user} && $options{current_user} eq $self->user_id)) {
        $out->{extended} = $self->extended;
        $out->{ip_address} = $self->ip_address;
        $out->{sso} = $self->sso;
    }
    if ($options{include_relationships}) {
        $out->{_relationships}{user} = '/api/user/'.$self->user_id;
    }
    if ($options{include_related_objects}) {
        $out->{user} = $self->user->describe;
    }
    return $out;
}

no Moose;
__PACKAGE__->meta->make_immutable;
