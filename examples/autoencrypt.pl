#!/usr/bin/perl

# Please don't encrypt me!
  
use Filter::CBC "Rijndael","my secret key","hex";

# This file will be encrypted and overwritten.
# Make backups, damnit!
# Autoencryption example
print "Don't try this at home, kids !";
