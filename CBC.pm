package Filter::CBC;

use strict;
use vars qw($VERSION $cipher $textmode);
use Filter::Util::Call ;
use Crypt::CBC;

$VERSION = '0.0.2';

sub import {
my ($type) = shift @_;
my $algorithm = shift;
my $key = shift;
$textmode = shift if @_;
my ($ref) = [] ;
$cipher = new Crypt::CBC($key,$algorithm);
filter_add(bless $ref) ;
}

sub filter {
my ($self) = @_ ;
my ($status) ;
if (($status = filter_read()) > 0)
{ s/([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg if $textmode eq "hex";
  $_ = unpack("u",$_) if $textmode eq "uudecode";
  $_ = $cipher->decrypt($_);
}
$status ;
}

1;
__END__
=pod

=head1 NAME

Filter::CBC - Source filter for Cipher Block Chaining

=head1 SYNOPSIS

  use Filter::Hex; use Filter::CBC "Rijndael","my secret key";

  52616e646f6d4956d6da837a7590d113f67d363b95eae044ac74937c2b7fc9dbaffb59656abebf5b69a50559bc9b4233

  -or-

  use Filter::CBC "Rijndael","my secret key","hex";

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

=head1 INTERNAL CBC HANDLERS

The following parameters can be passed as part of the CBC encryption routine

=item Rijndael

=over 3

This is the AES (Advanced Encryption Scheme) routine. You need 
Crypt::Rijndael for this.

=back 3

=item DES

=over 3

This is the DES routine. You need Crypt::DES for this.

=back 3

=item IDEA

=over 3

This is the IDEA routine. You need Crypt::IDEA for this.

=back 3

=item Blowfish

=over 3

This is the Blowfish routine. You need Crypt::Blowfish for this.

=back 3


But any CBC Compatible routine will work.

=head1 INTERNAL TEXT HANDLERS

The following parameters can be passed as part of the internal text handling.

=item hex

=over 3

If the encrypted code is converted to hex values, you need to use this
parameter first. Source filters can't handle binary data properly.

=back 3

=item uudecode

=over 3

If the encrypted code is uuencoded, you need to use this parameter first. 
Source filters can't handle binary data properly.

=back 3

If you don't pass a parameter for text handling, Filter::CBC will try to
decrypt the code anyway. If the encrypted code is clean enough (for example
when using Rot13 encryption), Text handling isn't necessary. In all other
cases you need to stack a filter so the encrypted code is handled properly.

The following example uses Filter::Hex instead of the internal Text handler
for hex converted encrypted code.

  use Filter::Hex; use Filter::CBC "Rijndael","my secret key";

  52616e646f6d4956d6da837a7590d113f67d363b95eae044ac74937c2b7fc9dbaffb59656abebf5b69a50559bc9b4233

=head1 REQUIREMENTS

Filter::CBC requires the following modules (depending on your needs)

=item Filter::Util::Call

=item Crypt::CBC

=item Crypt::Rijndael

=item Crypt::DES

=item Crypt::IDEA

=item Crypt::Blowfish

=head1 THANKS A MILLION

Alot of thanks to Ray Brinzer (Petruchio on Perlmonks) for giving an example
on how to handle parameters with use.

=head1 TODO

A bit less then first release but still plenty.

=head1 DISCLAIMER

This code is released under GPL (GNU Public License). More information can be 
found on http://www.gnu.org/copyleft/gpl.html

=head1 VERSION

This is Filter::CBC 0.0.2.

=head1 AUTHOR

Hendrik Van Belleghem (beatnik@quickndirty.org)

=head1 SEE ALSO

GNU & GPL - http://www.gnu.org/copyleft/gpl.html

Filter::Util::Call (http://search.cpan.org/search?dist=Filter)

Crypt::CBC (http://search.cpan.org/search?dist=Crypt-CBC)

Crypt::Rijndael (http://search.cpan.org/search?dist=Crypt-Rijndael)

Crypt::DES (http://search.cpan.org/search?dist=Crypt-DES)

Crypt::IDEA (http://search.cpan.org/search?dist=Crypt-IDEA)

Crypt::Blowfish (http://search.cpan.org/search?dist=Crypt-Blowfish)

Paul Marquess' article
on Source Filters (http://www.samag.com/documents/s=1287/sam03030004/)

=cut
