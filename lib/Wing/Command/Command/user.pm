package Wing::Command::Command::user;

use Wing;
use Wing::Perl;
use Wing::Command -command;
use Ouch;
use Encode qw(encode);

sub abstract { 'manage users' }

sub usage_desc { 'Add and modify user accounts.' }

sub description {'Examples:
wing user --add=Joe --password=123qwe --admin

wing user --modify=Joe --noadmin --username=joseph

wing user --search=jo
'}

sub opt_spec {
    return (
      [ 'add=s', 'add a new user' ],
      [ 'modify=s', 'change an existing user' ],
      [ 'search=s', 'search users by keyword' ],
      [ 'list', 'list all users' ],
      [ 'list_admins', 'list all admin users' ],
      [ 'email=s', 'the email address for the user' ],
      [ 'password=s', 'the password for the user' ],
      [ 'username=s', 'a new username for the user' ],
      [ 'role=s', 'a new role for the user' ],
      [ 'status=s', 'a new status for the user' ],
      [ 'admin!', 'whether the user should be an admin' ],
    );
}

sub validate_args {
    my ($self, $opt, $args) = @_;
    # no args allowed but options!
    $self->usage_error("No args allowed, only options.") if @$args;
}

sub list_users {
    my $resultset = shift;
    my $users = $resultset->search(undef, {order_by => 'username'});
    while (my $user = $users->next) {
        my $suffix = '';
        if ($user->admin) {
            $suffix = ' (admin)';
        }
        say encode('UTF-8', $user->username.$suffix);
    }
    say 'Total: ', $resultset->count;
}

sub add_user {
    my ($users, $username, $password, $admin, $email, $role) = @_;
    my $user = $users->new({});
    $user->username($username);
    $user->admin($admin) if $admin;
    $user->email($email);
    $user->role($role) if $role;
    $user->encrypt_and_set_password($password);
    $user->insert;
}

sub modify_user {
    my ($users, $old_username, $new_username, $password, $admin, $email, $role, $status) = @_;
    my $user = $users->search({username => $old_username}, { rows => 1})->single;
    ouch(440, $old_username.' not found.') unless defined $user;
    $user->encrypt_and_set_password($password) if defined $password;
    $user->admin($admin) if defined $admin;
    $user->username($new_username) if defined $new_username;
    $user->email($email) if defined $email;
    $user->role($role) if defined $role;
    $user->contributor_status($status) if defined $status;
    $user->update;
}

sub execute {
    my ($self, $opt, $args) = @_;
    my $users = Wing->db->resultset('User');
    if ($opt->{add}) {
        eval { add_user($users, $opt->{add}, $opt->{password}, 
			$opt->{admin}, $opt->{email}, $opt->{role}) };
        say($@ ? bleep : $opt->{add}. ' created'); 
    }
    elsif ($opt->{modify}) {
        eval { modify_user($users, $opt->{modify}, $opt->{username}, $opt->{password}, 
			   $opt->{admin}, $opt->{email}, $opt->{role}, $opt->{status}) };
        say($@ ? bleep : $opt->{modify}. ' updated'); 
    }
    elsif ($opt->{search}) {
        my $list = $users->search({username => { like => '%'.$opt->{search}.'%'}});
        list_users($list);
    }
    elsif ($opt->{list}) {
        my $list = $users->search;
        list_users($list);
    }
    elsif ($opt->{list_admins}) {
        my $list = $users->search({admin => 1});
        list_users($list);
    }
    else {
        say "You must specify --add or --modify.";
    }
}


1;

=head1 NAME

wing user - Add and modify user accounts.

=head1 SYNOPSIS

 wing user --add=Joe --password=123qwe --admin --email=joe@blow.com

 wing user --modify=Joe --noadmin --username=joseph

 wing user --search=jo
 
=head1 DESCRIPTION

This provides simple user management. For all complex function, you should use the web interface. 

=head1 AUTHOR

Copyright 2012-2013 Plain Black Corporation.

=cut
