# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $loaded;}
use Filter::CBC 'Rijndael','Filter::CBC test','hex';

52616e646f6d49568c3056710ba974775b0dce2948dba4eef9840823064dc464f76c1f25c1667e3b9afb34850ed9defa
