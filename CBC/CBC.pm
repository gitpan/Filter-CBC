package Filter::CBC;

use strict;
use vars qw($VERSION $cipher);
use Filter::Util::Call ;
use Crypt::CBC;

$VERSION = '0.01';

my $cipher;

sub import {
my ($type) = shift @_;
my $algorithm = shift;
my $key = shift;
my ($ref) = [] ;
$cipher = new Crypt::CBC($key,$algorithm);
filter_add(bless $ref) ;
}

sub filter {
my ($self) = @_ ;
my ($status) ;
$_ = $cipher->decrypt($_) if ($status = filter_read()) > 0 ;
$status ;
}

1;
__END__
=head1 NAME

Filter::CBC - Source filter for Cipher Block Chaining

=head1 SYNOPSIS

  use Filter::Hex; use Filter::CBC "Rijndael","my secret key";

  52616e646f6d4956d6da837a7590d113f67d363b95eae044ac74937c2b7fc9dbaffb59656abebf5b69a50559bc9b4233

=head1 DESCRIPTION

Filter::CBC is a Source filter that uses Cipher Block Chaining (CBC) to
encrypt your code. The tricky part is that most CBC Algorithms have binary
output. Filter::Hex bypasses this obstacle. By stacking source filters, the
encrypted code is first converted from HEX to plain CBC readable data. After
that the appropriate algorithm and keyphrase are used to decrypt it.

=head1 DOWNSIDES

Speed

Source filters are slow. VERY Slow. Filter::CBC is not an exception.
Well uhm kinda. Filter::CBC is even slower. Be warned, be VERY VERY warned.

=head1 TODO

Loads probably. This is a very early draft.

=head1 DISCLAIMER

This code is released under GPL (GNU Public License). More information can be 
found on http://www.gnu.org/copyleft/gpl.html

=head1 VERSION

This is Filter::CBC 0.0.1.

=head1 AUTHOR

Hendrik Van Belleghem (beatnik@quickndirty.org)

=head1 SEE ALSO

GNU & GPL - http://www.gnu.org/copyleft/gpl.html

=cut
