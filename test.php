#! /usr/bin/php -d enable_dl=on
<?php
dl('iptables.so');
//suck_my_balls("bitch");

//$policy = ipt_get_policy();
//$policy = ipt_get_policy("INPUT");
//echo "policy= $policy\n";
//echo "policy= ", ipt_get_policy("FORWARD"), "\n";

ipt_set_policy('FORWARD', 'DROP');
$chain = array('INPUT', 'FORWARD');
foreach ($chain as $c) {
  echo "policy for $c: ", ipt_get_policy($c), "\n";
}
