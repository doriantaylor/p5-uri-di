use inc::Module::Install;

name     'URI-di';
abstract 
    'Implementation of the di: URI scheme from draft-hallambaker-digesturi';
all_from 'lib/URI/di.pm';
author   q{Dorian Taylor <dorian@cpan.org>};
license  'apache';

requires 'URI';
requires 'Digest';
requires 'MIME::Base64';

build_requires 'Test::More';

auto_install;

WriteAll;

