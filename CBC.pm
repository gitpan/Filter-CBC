package Filter::CBC;

use strict;
use vars qw($VERSION $cipher $textmode %Algorithms);
use Filter::Util::Call ;
use Crypt::CBC;

my %Algorithms =
("RIJNDAEL"=>"Rijndael",
 "DES"=>"DES",
 "IDEA"=>"IDEA",
 "BLOWFISH"=>"Blowfish",
 "GOST"=>"GOST",
 "DES_EDE3"=>"DES_EDE3",
 "TWOFISH"=>"Twofish",
 "NULL"=>"NULL",
 "TEA"=>"TEA");

$VERSION = '0.05';

sub import {
my ($type) = shift @_;
my $algorithm = shift || "Rijndael";
$algorithm = $Algorithms{uc $algorithm} || $algorithm;
my $key = shift || "This space is left blank intentionally";
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
  #$_ = unpack("u",$_) if $textmode eq "uudecode";
  $_ = $cipher->decrypt($_);
}
$status ;
}

open(F,"<$0") || die $!;
my ($past_use,$textmode,$key,$algorithm);
my @code = ();
while(<F>)
{ $|++;
  if (!$past_use)
  { ($algorithm,$key,undef,$textmode) = /use Filter\:\:CBC\s*[\'\"](\w*)[\'\"]\s*\,\s*[\'\"]([^\'\"]*)[\'\"](\,[\'\"](\w*)[\'\"])?/; }
  if (defined $algorithm && defined $key && !$past_use) { $past_use++; push(@code ,$_); next;}
  if ($past_use && defined $key && defined $algorithm)
  { my (@foo) = <F>;
    unshift (@foo,$_);
    my $code = join("",@foo);
    $algorithm ||= "Rijndael";
    $algorithm = $Algorithms{uc $algorithm} || $algorithm;
    $key ||= "This space is left blank intentionally";
    if ($code =~ /\;/)
    { my $cipher = new Crypt::CBC($key,$algorithm);
      $code = $cipher->encrypt($code);
      if ($textmode eq "hex") { $code = unpack("H*",$code); }
      open(OUTFILE,">$0.bak") || die $!;
      print OUTFILE @code,$code;
      close(OUTFILE);
      unlink("$0") || die $!;
      rename ("$0.bak",$0);
      exit;
    }
  } 
  else { push(@code,$_); }
}
close(F);

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

  -or-

  # Please don't encrypt me!

  use Filter::CBC "Rijndael","my secret key","hex";

  # This file will be encrypted and overwritten.
  # Make backups, damnit!
  # Autofilter example
  print "Don't try this at home, kids !";

  -or-

  # Please don't encrypt me!

  use Filter::CBC "","","hex";

  # This file will be encrypted and overwritten.
  # Make backups, damnit!
  # Autofilter example
  # Defaults will be used
  # Rijndael is default encryption algorithm
  # Default keyphrase is : This space is left blank intentionally
  print "Don't try this at home, kids !";


=head1 DESCRIPTION

Filter::CBC is a Source filter that uses Cipher Block Chaining (CBC) to
encrypt your code. The tricky part is that most CBC Algorithms have binary
output. The textmode bypasses this obstacle, by converting the data to less scary data.

=head1 DOWNSIDES

=item *
Source filters are slow. VERY Slow. Filter::CBC is not an exception.
Well uhm kinda. Filter::CBC is even slower. Be warned, be VERY VERY warned.

=item *
You're source file is overwrittten when you're using the autoefilter feature.


=head1 PARAMETERS

The three parameters that can be passed along are :

=over 2

=item CBC Handler

This parameter indicates what CBC encryption routine to use. Possible values are described in the next section.

=item Keyphrase

This parameter is the keyphrase for the encryption routine described as previous parameter.

=item Text Handler

This optional parameter is the textmode. See INTERNAL TEXT HANDLERS

=back

=head1 INTERNAL CBC HANDLERS

The following parameters can be passed as part of the CBC encryption routine

=over 2

=item Rijndael

This is the AES (Advanced Encryption Scheme) routine. You need 
Crypt::Rijndael for this.

=item DES

This is the DES routine. You need Crypt::DES for this.

=item IDEA

This is the IDEA routine. You need Crypt::IDEA for this.

=item Blowfish

This is the Blowfish routine. You need Crypt::Blowfish for this.

=item GOST

This is the GOST routine. You need Crypt::GOST for this.

=item DES_EDE3

This is the Triple DES routine. You need Crypt::DES_EDE3 for this.

=item Twofish

This is the Twofish routine. You need Crypt::Twofish for this.

=item NULL

This is the NULL routine. You need Crypt::NULL for this.

=item TEA

This is the TEA routine. You need Crypt::TEA for this.

=back

But any CBC Compatible routine will work.

=head1 INTERNAL TEXT HANDLERS

The following parameters can be passed as part of the internal text handling.

=over 2

=item hex

If the encrypted code is converted to hex values, you need to use this
parameter first. Source filters can't handle binary data properly.

=item uudecode

uudecoding has been disabled in the current source tree.

If the encrypted code is uuencoded, you need to use this parameter first. 
Source filters can't handle binary data properly. Using this textmode is not 
recommended since the autofilter feature scans for keys which also are used 
in the uudecode algorithm.

=back

If you don't pass a parameter for text handling, Filter::CBC will try to
decrypt the code anyway. If the encrypted code is clean enough (for example
when using Rot13 encryption), Text handling isn't necessary. In all other
cases you need to stack a filter so the encrypted code is handled properly.

The following example uses Filter::Hex instead of the internal Text handler
for hex converted encrypted code.

  use Filter::Hex; use Filter::CBC "Rijndael","my secret key";

  52616e646f6d4956d6da837a7590d113f67d363b95eae044ac74937c2b7fc9dbaffb59656abebf5b69a50559bc9b4233

=head1 AUTOFILTERING

Since Filter::CBC 0.04, using code2cbc isn't required anymore. Filter::CBC can encrypt your code
on the fly if it's not yet encrypted. Be warned that your source file is overwritten. You can use
cbc2code.pl to decrypt your encrypted code. BACKUP!

  use Filter::CBC "Rijndael","my secret key","hex";

  # This file will be encrypted and overwritten.
  # Make backups, damnit!
  # Autofilter example
  print "Don't try this at home, kids !";

This code will be encrypted the first time you run it. Everything before the 'use Filter::CBC' line is kept
intact.

=head1 DEFAULTS

=over 3

=item Encryption routine

=back

Filter::CBC will use Rijndael when no encryption algorithm is defined.

=over 3

=item Keyphrase

=back

Filter::CBC will use the following line when no keyphrase is defined :

=over 5

    This space is left blank intentionally

=back

=head1 REQUIREMENTS

Filter::CBC requires the following modules (depending on your needs)

=over 3

=item Filter::Util::Call

=item Crypt::CBC

=item Crypt::Rijndael

=item Crypt::DES

=item Crypt::IDEA

=item Crypt::Blowfish

=item Crypt::GOST

=item Crypt::DES_EDE3

=item Crypt::Twofish

=item Crypt::NULL

=item Crypt::TEA

=back

=head1 THANKS A MILLION

Alot of thanks to Ray Brinzer (Petruchio on Perlmonks) for giving an example
on how to handle parameters with use.

=head1 TODO

A bit less then first release but still plenty.

Work around the uudecode bug.

=head1 DISCLAIMER

This code is released under GPL (GNU Public License). More information can be 
found on http://www.gnu.org/copyleft/gpl.html

=head1 VERSION

This is Filter::CBC 0.05.

=head1 AUTHOR

Hendrik Van Belleghem (beatnik -at- quickndirty -dot- org)

=head1 SEE ALSO

GNU & GPL - http://www.gnu.org/copyleft/gpl.html

Filter::Util::Call - http://search.cpan.org/search?dist=Filter

Crypt::CBC - http://search.cpan.org/search?dist=Crypt-CBC

Crypt::Rijndael - http://search.cpan.org/search?dist=Crypt-Rijndael

Crypt::DES - http://search.cpan.org/search?dist=Crypt-DES

Crypt::IDEA - http://search.cpan.org/search?dist=Crypt-IDEA

Crypt::Blowfish - http://search.cpan.org/search?dist=Crypt-Blowfish

Crypt::GOST - http://search.cpan.org/search?dist=Crypt-GOST

Crypt::DES_EDE3 - http://search.cpan.org/search?dist=Crypt-DES_EDE3

Crypt::Twofish - http://search.cpan.org/search?dist=Crypt-Twofish

Crypt::NULL - http://search.cpan.org/search?dist=Crypt-NULL

Crypt::TEA - http://search.cpan.org/search?dist=Crypt-TEA

Paul Marquess' article
on Source Filters - http://www.samag.com/documents/s=1287/sam03030004/

=cut
