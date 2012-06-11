#!perl

use strict;
use warnings;

use Test::More qw(no_plan);
use URI;

use_ok('URI::di');

# the data from __DATA__
my $hglaguaghlag = URI->new
    ('di:sha-256;AekWTPh53Qxi8rO53fjFQQbUl_CUN5t0q-2lyJHIqZ4');

ok($hglaguaghlag, 'URI constructor with di: scheme');
isa_ok($hglaguaghlag, 'URI::di');

my %q = (ct => 'text/plain', http => ['foo.com', 'bar.com']);

ok(my $uri = URI::di->compute(\*DATA), 'Constructor with GLOB');

ok($uri->eq($hglaguaghlag), 'URIs match');

ok($uri->digest, 'Binary digest returns a value');

my $hex = '01e9164cf879dd0c62f2b3b9ddf8c54106d497f094379b74abeda5c891c8a99e';

is($uri->hexdigest, $hex, 'Hex digests match');

is($uri->algorithm, 'sha-256', 'Algorithm matches');


__DATA__
hglaguaghlag
