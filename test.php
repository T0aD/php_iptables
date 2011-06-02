#! /usr/bin/php -d enable_dl=on
<?php
dl('iptables.so');
//suck_my_balls("bitch"); // super works
/*
ipt_set_policy('FORWARD', 'DROP');
$chain = array('INPUT', 'FORWARD');
foreach ($chain as $c) {
  echo "policy for $c: ", ipt_get_policy($c), "\n"; // works
}
$rv = ipt_create_chain('aris_le_belge');

*/
//$rv = ipt_delete_chain('aris_le_belge');
//ipt_get_chains();

//$rv = ipt_create_chain('INPUT'); // works
//$rv = ipt_create_chain('aris_le_belgeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'); // works

if (! ipt_is_chain('chez_leon')) {
  ipt_create_chain('chez_leon');
 }

$fp = fopen('trapped', 'r');
while ($l = fgets($fp, 256)) {
  $l = trim($l);
  //  echo "ip to add: $l\n";
  fw_addIP('smtpbl', $l);
  break;
 }
fclose($fp);

function fw_addIP($name, $ip) {
  //  echo "adding ip $ip\n";
  $ip_t = explode('.', $ip);
  $subnet8 = $ip_t[0];
  $subnet16 = $ip_t[0].'.'.$ip_t[1];
  $subnet24 = $ip_t[0].'.'.$ip_t[1].'.'.$ip_t[2];

  $chain = s('%s-list', $name);
  chain_create($chain);
  chain_create(s("smtpbl-list-%s-8", $subnet8));
  rule_create($chain, s('%s.0.0.0/8', $subnet8), s('smtpbl-list-%s-8', $subnet8));

  chain_create(s("smtpbl-list-%s-16", $subnet16));
  rule_create(s('smtpbl-list-%s-8', $subnet8), s('%s.0.0/16', $subnet16),
              s('smtpbl-list-%s-16', $subnet16));

  chain_create(s("smtpbl-list-%s-24", $subnet24));
  rule_create(s('smtpbl-list-%s-16', $subnet16), s('%s.0/24', $subnet24),
              s('smtpbl-list-%s-24', $subnet24));

  rule_create(s('smtpbl-list-%s-24', $subnet24), $ip, 'chez_leon');
}
function s($format, $value) {
  return sprintf($format, $value);
}
function chain_create($chain) {
  if (! ipt_is_chain($chain)) {
    ipt_create_chain($chain);
  }
}
function rule_create($chain, $source, $target) {
  if (! rule_exists($chain, $source, $target)) {
    //    ipt_insert_rule($chain, $source, $target);
    ipt_do_command(sprintf('-I %s -s %s -j %s', $chain, $source, $target));
  }
}

function rule_exists($chain, $source, $target) {
  return false;
}
