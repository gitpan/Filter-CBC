#!/usr/bin/perl

use strict;
use Crypt::CBC;

print "Enter algorithm : ";
my $algo = <STDIN>;
chomp $algo;

print "Enter Keyphrase : ";
my $key = <STDIN>;
chomp $key;

print "Enter Text handler (hex|uudecode) : ";
my $text = <STDIN>;
chomp $text;

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
if ($text eq "hex") { $code = unpack("H*",$code); }
if ($text eq "uudecode") { $code = pack("u",$code); }
open(OUTFILE,">$file.out") || die $!;
print OUTFILE "#Initialize stuff here\n\n";
print OUTFILE "use Filter::CBC '$algo','$key'";
if ($text) { print OUTFILE ",'$text'"; }
print OUTFILE ";\n\n";
print OUTFILE $code;
close(OUTFILE);