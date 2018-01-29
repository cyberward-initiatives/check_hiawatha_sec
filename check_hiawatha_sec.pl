#!/usr/bin/env perl -w

#####################################################
#
# Script for checking hiawatha logfile (system.log),
# for banned IPs and so on
#
# Author: solacol
# Version: 0.3
#
#####################################################
#
#
# TODO:
# - hiawatha extended logfile format is needed (only this suppported now)
# - unknown state
# - system.log.{1..n} should be checked to, at least to a certain level
#
# CHANGE-LOG:
# - verbose mode output with newline at the end
# - fixed bug causing ignored "unbanned"
# - fixed bug counter not increasing
#
###


use strict;
use warnings;


my $logfile = $ARGV[0];
my $time_period = $ARGV[1];
my $warn_thres = $ARGV[2];
my $mode = $ARGV[3];
my %h_ips = ();
my %h_ips_counter = (); # a second hash because I m too lazy to use references
my @a_results_crit = ();
my @a_results_warn = ();

my %h_errors = (
	'OK' => 0,
	'WARNING' => 1,
	'CRITICAL'=> 2,
	'UNKNOWN' => 3
	);


# Check if mandatory arguments are given and defined
die("HELP: scriptname logfile [check_period in hours] [warning_threshold] [quiet|verbose]") unless(defined($logfile));

# Set time period for checking to 24h if not given
$time_period = 24 unless(defined($time_period) && $time_period =~ m/[[:digit:]]/);

# Set warning threshold to 5 if not given
$warn_thres = 5 unless(defined($warn_thres) && $warn_thres =~ m/[[:digit:]]/);

# Set mode to quiet if not given
$mode = 'quiet' unless(defined($mode) && ($mode eq 'quiet' || $mode eq 'verbose'));

# Get current time and set it according to time period to check (in epoch)
my $current_date = `/bin/date \+\%s`;
my $check_period = `/bin/date \+\%s \-d \"\- $time_period hours\"`;

# Grep all lines of logfile ... this could also be done with readin/while ... but not on my system ;-)
my @a_logfile = `/usr/bin/sudo /bin/grep \\.\\* $logfile`;

foreach my $line (@a_logfile){
	chomp($line);
	# Skip if not starting with IP or keyword existent
	next if($line !~ m/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\|/);
	next if($line !~ m/banned|kicked/i);
	my @a_split = split('\|',$line);
	# Compare timestamp to check period and skip if to old
	my $timestamp = `date \-d \"$a_split[1]\" \+\%s`;
	chomp($timestamp);
	next if($timestamp <= $check_period);
	my $ip = $a_split[0];
	chomp($ip);
	my $info = $a_split[-1];
	chomp($info);
	if(exists $h_ips{$ip}){
		if($info =~ m/unbanned/i){
			my $count = $h_ips_counter{$ip};
			$h_ips_counter{$ip} = $count+1;
			$h_ips{$ip} = $info;
		}
		next;
	}
	else{
		$h_ips{$ip} = $info;
		$h_ips_counter{$ip} = 1;
	
	}
}

# All relevant hash entries to array
foreach my $ip (keys %h_ips){
	push(@a_results_crit,"$ip|$h_ips{$ip}") if($h_ips{$ip} !~ m/unbanned/i);
}

foreach my $ip (keys %h_ips_counter){
	push(@a_results_warn,"$ip|$h_ips_counter{$ip}") if($h_ips_counter{$ip} > $warn_thres);
}

# State check and array elements to string
if(scalar(@a_results_crit) > 0){
	my $result = 'CRIT - '.scalar(@a_results_crit).' IPs are fucked (use verbose mode immediately)';
	if($mode eq 'verbose'){
		$result = join("\n",@a_results_crit);
		$result = $result."\n";
	}
	print("$result");
	exit($h_errors{'CRITICAL'});
}
elsif(scalar(@a_results_warn) > 0){
	my $result = 'WARN - '.scalar(@a_results_warn).' IPs are suspicious (use verbose mode)';
	if($mode eq 'verbose'){
		$result = join("\n",@a_results_warn);
                $result = $result."\n";
	}
	print("$result");
	exit($h_errors{'WARNING'});
}
else{
	my $result = "Seems to be fine for the last $time_period hours ... at least according to $logfile";
	if($mode eq 'verbose'){
		$result = $result."\n";
	}
	print("$result");
	exit($h_errors{'OK'});
}
