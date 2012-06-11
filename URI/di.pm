package URI::di;

require URI;
require URI::_query;
require URI::_punycode;
require URI::QueryParam;
@ISA=qw(URI::_query URI);

$VERSION = '0.01';

# not sure why the module is laid out like this, oh well.

=head1 NAME

URI::di - URI scheme for digital signatures

=head1 SYNOPSIS

    use URI;

    $u = URI->new('di:sha-256');
    $u->compute('some data');

    my $algo = $u->algorithm;
    my $b64  = $u->b64digest;
    my $hex  = $u->hexdigest;
    my $bin  = $u->digest;

=head1 DESCRIPTION

This module implements the C<di:> URI scheme laid out in
L<draft-hallambaker-digesturi|http://tools.ietf.org/html/draft-hallambaker-digesturi-02>.

=cut

use strict;
use warnings; # FATAL => 'all';

use MIME::Base64 qw(encode_base64 decode_base64);
use URI::Escape  qw(uri_unescape);

use Digest;
use Carp         ();
use Scalar::Util ();

# XXX please don't go away from Digest
my %ALGOS = map { lc $_ => 1 } keys %Digest::MMAP;

=head2 compute $DATA [, $ALGO, \%QUERY]

Compute a new di: URI from some data. Since the data objects we're
typically interested in hashing tend to be bulky, this method will
optionally take GLOB or SCALAR references, even blessed ones if you
can be sure they'll behave, that is, globs treated like files and
scalars dereferenced. If not, C<$DATA> can also be a CODE reference as
well, with the L<Digest> context as its first argument, enabling you
to specify your own behaviour, like this:

    my $obj = MyObj->new;

    my $di = URI->new('di:sha-256;');
    $di->compute(sub { shift->add($obj->as_string) });

    # Alternatively:

    use URI::di;

    my $di = URI::di->compute(sub { shift->add($obj->as_string) });

The algorithms supported are the same as the ones in L<Digest>, which
will be coerced to lower-case in the URI. If omitted, the default
algorithm is SHA-256, per the draft spec.

Optionally, you can pass in a string or HASH reference which will be
appended to the URI. The keys map as they do in L<URI::QueryParam>,
and so do the values, which can be either strings or ARRAY references
containing strings, to represent multiple values.

=cut

sub compute {
    my ($self, $data, $algo, $query) = @_;
    Carp::croak('Compute constructor must have some sort of data source.')
          unless defined $data;

    $algo = $algo ? lc $algo : 'sha-256';
    $self = ref $self ? $self->clone : URI->new("di:$algo");
    # one last time
    $algo = lc $self->algorithm;
    Carp::croak("Algorithm $algo isn't on the menu.")
          unless $ALGOS{$algo};

    # of course the chief wants it in upper case
    my $ctx = Digest->new(uc $algo);

    # oh man this is too damn clever. it is bound to screw up.
    my %handler = (
        GLOB   => sub { binmode $_[0]; $ctx->addfile($_[0]) },
        SCALAR => sub { $ctx->add(${shift()}) },
        CODE   => sub { shift->($ctx) },
    );

    if (ref $data) {
        my $ok;
        for my $type (keys %handler) {
            # XXX is there a less dumb way to do this?
            $ok = Scalar::Util::blessed($data) ?
                $data->isa($type) : ref $data eq $type;
            if ($ok) {
                $handler{$type}->($data);
                last;
            }
        }
        Carp::croak('If the data is a reference, it has to be' .
                        ' some kind of GLOB or SCALAR.') unless $ok;
    }
    else {
        $ctx->add($data);
    }

    my $digest = $ctx->b64digest;
    $digest =~ tr!+/!-_!;

    $self->opaque("$algo;$digest");
    # XXX do something smarter with the query
    $self->query_form_hash($query) if $query;

    $self;
}

=head2 algorithm

Retrieves the hash algorithm. This method is read-only, since it makes
no sense to change the algorithm of an already-computed hash.

=cut

sub algorithm {
    my $self = shift;
    my $o = $self->opaque;
    return unless defined $o;
    $o =~ s/^(.*?)(;.*)?$/$1/;
    $o;
}

=head2 b64digest [$RAW]

Returns the digest encoded in Base64. An optional C<$RAW> argument
will return the digest without first translating from I<base64url>
(section 5 in L<RFC 4648|http://tools.ietf.org/html/rfc4648#section-5>).

Like everything else in this module that pertains to the hash itself,
this accessor is read-only.

=cut

sub b64digest {
    my ($self, $raw) = @_;
    my $hash = $self->opaque;
    $hash =~ s/^(?:.*?;)(.*?)(?:\?.*)?$/$1/;
    $hash =~ tr!-_!+/! unless $raw;
    $hash;
}

=head2 hexdigest

Returns the hexadecimal cryptographic digest we're all familiar with.

=cut

sub hexdigest {
    unpack 'H*', shift->digest;
}

=head2 digest

Retrieves a binary digest, in keeping with the nomenclature in
L<Digest>.

=cut

sub digest {
    MIME::Base64::decode_base64(shift->b64digest);
}

=head2 locators

Gets or sets the locators defined in L<section
2.1.4|http://tools.ietf.org/html/draft-hallambaker-digesturi-02#section-2.1.4>
as URI objects.

=cut

=head2 key

=cut

package URI::di::CryptoSpec;

use overload '""' => \&as_string;

sub new {
    my ($class, $string) = @_;
    bless \$string, $class;
}

sub cipher {
    my $self = shift;
    my $s = $$self;
    $s =~ /^(.*?)(:.*)?$/;
    $1;
}

sub key {
    my $self = shift;
    my $s = $$self;
    $s =~ /^(?:[^:]+:)([^:]*?)(:.*)?$/;
    $1;
}

sub iv {
    my $self = shift;
    my $s = $$self;
    $s =~ /^(?:[^:]+:){2}(.*?)$/;
    $1;
}

sub as_string {
    ${$_[0]};
}

1;

__END__
