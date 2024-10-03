package Wing::Rest::Session;

use Wing::Perl;
use Ouch;
use Wing::Session;
use Dancer;
use Wing::Rest;
use Wing::SSO;


del '/api/session/:id' => sub {
    Wing::Session->new(id => params->{id}, db => site_db())->end;
    return { success => 1 };
};

get '/api/session/:id' => sub {
    my $session = get_session(session_id => params->{id});
    return describe($session, current_user => eval { get_user_by_session_id() });
};

post '/api/login' => sub {
    
    ouch(400, 'You must specify a username', 'username') unless params->{username};
    ouch(400, 'You must specify a password', 'password') unless params->{password};
    
    # Look up the username.
    
    my $schema = site_db();
    my $username = params->{username};
    
    my $user = $schema->resultset('User')->search({username => $username},{rows=>1})->single;
    
    # If there is no matching username, look up by email.
    
    unless ( defined $user )
    {
	my @results = $schema->resultset('User')->search({email => $username });
	
	if ( @results == 1 )
	{
	    $user = $results[0];
	}
	
	elsif ( @results > 1 )
	{
	    ouch(400, 'Email is not unique');
	}
    }
    
    # Validate the username and password.
    
    ouch(401, 'Username or password incorrect') unless defined $user &&
	$user->is_password_valid(params->{password});
    
    # Check that this account is active.
    
    ouch(403, "This account is disabled")
	if $user->get_column('contributor_status') ne 'active';
    
    # Create a new login session.
    
    my $session = $user->start_session({ api_key_id => params->{api_key_id}, 
					 ip_address => request->remote_address });
    
    my $dbh = Wing->db->storage->dbh;
    
    my $session_id = $session->id;
    my $user_id = $user->get_column('id');
    my $password_hash = $user->get_column('password');
    my $role = $user->get_column('role');
    my $expire_days = $session->expire_days || 1;
    my $enterer_no = $user->get_column('person_no') || 0;
    my $authorizer_no = $user->get_column('authorizer_no') || 0;
    my $superuser = $user->get_column('admin') || 0;
    
    my $quoted_id = $dbh->quote($session_id);
    my $quoted_user = $dbh->quote($user_id);
    my $quoted_pw = $dbh->quote($password_hash);
    my $quoted_ip = $dbh->quote(request->remote_address || '127.0.0.1');
    my $quoted_role = $dbh->quote($role);
    my $quoted_exp = $dbh->quote($expire_days);
    my $quoted_ent = $dbh->quote($enterer_no);
    my $quoted_auth = $dbh->quote($authorizer_no);
    my $quoted_sup = $dbh->quote($superuser);
    
    my $db = Wing->config->get('content_db') || 'pbdb';
    
    my $sql = "INSERT INTO $db.session_data (session_id, user_id, password_hash, ip_address,
		    role, expire_days, superuser, enterer_no, authorizer_no)
		VALUES ($quoted_id, $quoted_user, $quoted_pw, $quoted_ip, $quoted_role,
		    $quoted_exp, $quoted_sup, $quoted_ent, $quoted_auth)";
    
    $dbh->do($sql);
    
    set_cookie session_id   => $session_id,
                expires     => '+1d',
                http_only   => 0,
                path        => '/';
    
    return describe($session, current_user => $user);
};

any '/api/logout' => sub {
    
    my $session = get_session();
    if (defined $session) {
	my $user = $session->user;
	$user->end_session($session) if $user;
    }
    #session->destroy; #enable if we start using dancer sessions
    
    return { success => 1 };
};



1;
