package Wing::Role::Result::TrendsLogHourly;

use Wing::Perl;
use Ouch;
use Moose::Role;
with 'Wing::Role::Result::Field';
with 'Wing::Role::Result::DateTimeField';

before wing_finalize_class => sub {
    my ($class) = @_;
    $class->wing_fields(
        name => {
            dbic 		=> { data_type => 'varchar', size => 60, is_nullable => 0 },
            view		=> 'public',
            edit		=> 'required',
            indexed     => 1,
        },
        value => {
            dbic 		=> { data_type => 'float', size => [15,2],  is_nullable => 0 },
            view		=> 'public',
            edit		=> 'required',
        },
    );
    $class->wing_datetime_field(
        hour           => {
            view                => 'public',
        },
    );
};

sub sqlt_deploy_hook {
    my ($self, $sqlt_table) = @_;
    $sqlt_table->add_index(name => 'idx_date_name_value', fields => ['hour','name','value']);
    $sqlt_table->add_index(name => 'idx_name_date', fields => ['name','hour']);
}

1;
