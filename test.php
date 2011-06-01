#! /usr/bin/php -d enable_dl=on
<?php
dl('iptables.so');
//suck_my_balls("bitch"); // super works

ipt_set_policy('FORWARD', 'DROP');
$chain = array('INPUT', 'FORWARD');
foreach ($chain as $c) {
  echo "policy for $c: ", ipt_get_policy($c), "\n"; // works
}
$rv = ipt_create_chain('aris_le_belge');
if (ipt_is_chain('chez_leon')) {
  echo "chain chez_leon exists\n";
 }
//$rv = ipt_create_chain('chez_leon');
$rv = ipt_delete_chain('aris_le_belge');
//$rv = ipt_delete_chain('aris_le_belge');
ipt_get_chains();

//$rv = ipt_create_chain('INPUT'); // works
//$rv = ipt_create_chain('aris_le_belgeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'); // works

