#!/usr/bin/perl

# This is a quick script to encrypt code with CBC
# Part of Filter::CBC.
# Same copyrights apply

use strict;
use Crypt::CBC;

print "Enter algorithm : ";
my $algo = <STDIN>;
chomp $algo;
print "Enter Keyphrase : ";
my $key = <STDIN>;
chomp $key;

print "Enter Filename with raw code : ";
my $file = <STDIN>;
chomp $file;

my $code;

open(FILE,"<$file") || die $!;
{ local($/);
  $code = <FILE>;
}
close(FILE);
  
my $cipher = new Crypt::CBC($key,$algo);
$code = $cipher->encrypt($code);
$code = unpack("H*",$code);
open(OUTFILE,">$file.out") || die $!;
print OUTFILE "#Initialize stuff here\n\n";
print OUTFILE "use Filter::Hex; use Filter::CBC '$algo','$key';\n\n";
print OUTFILE $code;
close(OUTFILE);