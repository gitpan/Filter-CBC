#!/usr/bin/perl

# CBC2CODE
# This small script will decrypt your Filter::CBC'ed code back to your
# plain code by reading the algorithm and the key.
# Using uudecode as textmode is NOT recommded !

# This script is part of Filter::CBC. Same license rules apply.

use strict;
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

print "Enter Filename with encrypted code : ";
my $file = <STDIN>;
chomp $file;

open(F,"<$file") || die $!;
my ($past_use,$textmode,$key,$algorithm);
my @code = ();
while(<F>)
{ if (!$past_use)
  { ($algorithm,$key,undef,$textmode) = /use Filter\:\:CBC\s*[\'\"](\w*)[\'\"]\s*\,\s*[\'\"]([^\'\"]*)[\'\"](\,[\'\"](\w*)[\'\"])?/; }
  if (defined $algorithm && defined $key && !$past_use) { $past_use++; push(@code ,$_); next;}
  if ($past_use && defined $key && defined $algorithm && $_ ne $/)
  { my (@foo) = <F>;
    unshift (@foo,$_);
    my $code = join("",@foo);
    $algorithm ||= "Rijndael";
    $algorithm = $Algorithms{uc $algorithm} || $algorithm;
    $key ||= "This space is left blank intentionally";
    my $cipher = new Crypt::CBC($key,$algorithm);
    $code =~ s/([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg if $textmode eq "hex";
    #$code = unpack("u",$_) if $textmode eq "uudecode";
    $code = $cipher->decrypt($code);
    open(OUTFILE,">$file.out") || die $!;
    print OUTFILE @code,$code;
    close(OUTFILE);
  } 
  else { push(@code,$_); }
}
close(F);
