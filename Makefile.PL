use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Filter::CBC',
    'VERSION_FROM' => 'CBC.pm', # finds $VERSION
    'PREREQ_PM' => {
         'Filter::Util::Call' => '1.05',
         'Crypt::CBC'         => '1.25',
	 'Crypt::Rijndael'    => '0.04',
     },
     'dist' => {COMPRESS=>'gzip',SUFFIX=>'gz'},
);

