package Filter::Hex;

use strict;
use Filter::Util::Call ;

# This module (or any one that filters text input to binary output) is 
# required since Source Filters apparently can't handle binary data properly.
# Part of Filter::CBC.
# Same copyrights apply

sub import {
my ($type) = @_ ;
my ($ref) = [] ;
filter_add(bless $ref) ;
}

sub filter {
my ($self) = @_ ;
my ($status) ;
s/([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg if ($status = filter_read()) > 0 ;
$status ;
}

1;