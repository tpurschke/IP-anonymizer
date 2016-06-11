#! /usr/bin/perl -w
# -------------------------------------------------------------------------------------------
# iso-anonymizer.pl
# run like this: 
# ./iso-anonymizer.pl [-txt-subst-file=/var/tmp/strings.txt] [-net="192.168.0.0/16"] <config-file1 config-file2 ...> 
# -------------------------------------------------------------------------------------------
require 5.006_000; # Needed for NetAddr::IP and file handler
require Exporter;
use strict;
use warnings;
use CGI qw(:standard);
use NetAddr::IP;
use Carp;
use Time::HiRes qw(time tv_interval); # for exact recording of script execution time

my ($cfg_file, $line);
our @ISA = qw(Exporter);
my $infile;
my $txt_subst_file;
my $net="10.0.0.0/8";
my $outfile;
my %anonymized_ip;	
my %anonymized_text;
my $ano_txt = "IsoAAAA";	# starting pattern - needs to be alpha chars only for incrementing to work
my $ano_suffix = '.iso-anonymized';

sub create_string_subst_hash {
	my $txt_subst_file_local = shift;
	open( my $txt_file, $txt_subst_file_local ) or croak "Unable to open $txt_subst_file_local: $!\n";
	while (my $line = <$txt_file>) {
		chomp ($line);
		$anonymized_text{$line} = $ano_txt;
		# adding separator chars (_-) contained in pattern again:
		if ($line =~ /.*?([\_\-])$/) { $anonymized_text{$line} .= $1; }	
		if ($line =~ /^([\_\-]).*?/) { $anonymized_text{$line} = $1 . $anonymized_text{$line}; }	
		++$ano_txt;
	}
	close ($txt_file);
	return;
}
sub _in_range { return 0 <= $_[0] && $_[0] <= 255; }

sub find_ipaddrs (\$&) {
    my($r_text, $callback) = @_;
    my $addrs_found = 0;
	my $regex = qr<(\d+)\.(\d+)\.(\d+)\.(\d+)(\/\d\d?)?>;

    $$r_text =~ s{$regex}{
        my $orig_match = join '.', $1, $2, $3, $4;
        if (defined($5) && $5 ne '') { $orig_match .= '/32'; }
        if ((my $num_matches = grep { _in_range($_) } $1, $2, $3, $4) == 4) {
            $addrs_found++;
            my $ipaddr = NetAddr::IP->new($orig_match);
            $callback->($ipaddr, $orig_match);
        } else {
            $orig_match;
        }
    }eg;
    return $addrs_found;
}

sub show_help {
	print ("---------------------------------------------------------------\n");
	print ("iso-anonyimzer (c) 2016 by Cactus eSecurity (https://cactus.de)\n");
	print ("---------------------------------------------------------------\n");
	print ("iso-anonyimzer can be used to substitute any occurence of ip addresses in a set of text files consistently.\n");
	print ("Might be helpful for anonymizing configuration files of routers, firewalls, etc. before handing them to third parties\n");
	print ("Consistently means that one ip is always substituted by the same destination ip address.\n");
	print ("All subnets, where identified as such, are replaced by /32 subnets. Does currently only handle IPv4 addresses.\n");
	print ("Additionally strings (e.g. customer names, etc.) can be (also consistently) replaced with generated anonymous strings starting with $ano_txt.\n");
	print ("Make sure that the string patterns do not contain any text that needs to stay unchanged in the output file.\n");
	print ("Note that anonymizing is performed consistently across all files. So if you need this multiple file consistency, \n");
	print ("make sure to anonymize all relevant files in a single run.\n");
	print ("\nSyntax:\n");
	print ("iso-anonymizer -help -txt-subst-file=<subst-filename> -net=<ip-subnet> <infile1> <infile2> ... <infilen>\n");
	print ("-help : displays this text (also when called without parameters)\n");
	print ("-txt-subst-file=<subst-filename> : optional, if parameter is set, substitutes all strings listed in <subst-filename> (one string per line)\n"); 
	print ("-net=<ip-subnet> : optional, defaults to '10.0.0.0/8' - ip subnet that is used for ip address substitution\n");
	print ("<infile1> <infile2> ... <infilen> : list of files to anonymize\n\n");
	print ("Example:\n");
	print ("iso-anonymizer -txt-subst-file=subst-strings.txt -net=192.168.88.0/24 file1.cfg file2.cfg file3.cfg\n\n");
}

sub anonymize {
	my $infile = shift;
	my $net = shift;
	my $outfile = shift;
	my $ip = NetAddr::IP->new("$net");

	open( my $ifh, $infile ) or croak "Unable to open $infile: $!\n";
	open( my $ofh, ">$outfile" ) or croak "Unable to open $outfile: $!\n" ;

	while (my $line = <$ifh>) {
		find_ipaddrs($line, sub {
			my($ipaddr, $orig) = @_;
			if ($orig =~ /^2[45][0258]\./) { # found netmask (assuming IPs starting with 24x.* and 25x.* are netmasks)
				return $anonymized_ip{$orig} if exists $anonymized_ip{$orig};
				$anonymized_ip{$orig} = "255.255.255.255"; # changing all netmask to /32 to avoid invalid cidrs
				return $anonymized_ip{$orig};
			} elsif ($orig eq '0.0.0.0') { 	# leave /0 netmask alone
				return $ipaddr->addr;
			} else {  
				my $netmask = '';
				if ($orig =~ /(.+?)\/32$/) {
					$orig = $1;
					$netmask = '/32';
				}
				return $anonymized_ip{$orig} . $netmask if exists $anonymized_ip{$orig};
				# if found ip has not yet an anonymous equivalent in hash - create new ip
				++$ip;
				$anonymized_ip{$orig} = $ip->addr;
				return $anonymized_ip{$orig} . $netmask;
			}
		});
		if (defined($txt_subst_file) && $txt_subst_file ne '') { # obfuscating text
			my $regex_all_texts = join("|", map {quotemeta} keys %anonymized_text);
			$line =~ s/($regex_all_texts)/$anonymized_text{$1}/go;
		}  
		print $ofh $line;
	}
	close ($ifh); close ($ofh); return;	
}

###########################
# main start
###########################

my $start_time = time();
my $query = CGI->new;
my $total_filesize = 0;

if ((defined($ARGV[0]) && $ARGV[0] eq "-help") || scalar($query->param)==0) { &show_help(); exit 0; }
if (defined(param("-txt-subst-file"))) { $txt_subst_file = param("-txt-subst-file"); &create_string_subst_hash($txt_subst_file); } 
	else { $txt_subst_file = ''; print ("no -txt-subst-file specified, not doing any string anonymizing\n"); }
if (defined(param("-net"))) { $net = param("-net"); } else { print ("no -net parameter specified, using default net $net\n"); }

# treating all params not starting with - as files to anonymize
# do not re-anonymize files with .anonymized extension and do not anonymize binary files
foreach my $file (@ARGV) { 
	if ($file !~ /^-/ && $file !~ /.*?$ano_suffix$/ && -T $file) {
		$total_filesize += -s $file;
		print ("anonymizing: $file ... "); 
		&anonymize($file, $net, $file . $ano_suffix);
		print ("result file = $file$ano_suffix\n"); 
	} else { if ($file !~ /^-/) { print ("ignoring file $file\n"); } }
}

# Generating statistics
my @ki=keys(%anonymized_ip);
my @kt=keys(%anonymized_text);
my $duration = time() - $start_time;
print("Anonymized " . ($#ki+1) . " ip addresses and " . ($#kt+1) . " strings in " . sprintf("%.1f",$duration) . " seconds");
printf(" (total %.2f MB, %.2f Mbytes/second).\n", $total_filesize/1000000, $total_filesize/$duration/1000000);
my $anonet = NetAddr::IP->new($net);
if ($anonet->num()<($#ki+1)) { 
	print("WARNING: generated "  . ($#ki+1) . " anonymized ip addresses (more than available in " . $anonet .
		" which can only hold " . $anonet->num() . " IP addresses).\n");
	print ("   Suggest to use bigger subnet if you need uniqueness of IP addresses.\n"); 
}
