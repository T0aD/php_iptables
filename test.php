#! /usr/bin/php -d enable_dl=on
<?php
dl('iptables.so');

if (0) {
$chains = iptc_get_chains();
foreach ($chains as $c) { iptc_flush_entries($c); }
foreach ($chains as $c) { iptc_delete_chain($c); }
iptc_commit();
exit();
 }

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

//iptc_free();

if (! iptc_is_chain('chez_leon2')) {
  //  iptc_create_chain('chez_leon2');
 }

$chains = iptc_get_chains();
//print_r($chains);
/*
for ($i = 0; $i < 10000; $i++) {
  iptc_inc();
 }
echo "count: ", iptc_get(), "\n";
*/

//exit();
//$rv = ipt_create_chain('INPUT'); // works
//$rv = ipt_create_chain('aris_le_belgeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'); // works

//ipt_do_command('-F');

//iptc_commit();
//iptc_commit();
//iptc_commit();
//exit();

$db32 = $db8 = $db16 = $db24 = array();

$fp = fopen('trapped', 'r');
while ($l = fgets($fp, 256)) {
  $l = trim($l);
  //  echo "ip to add: $l\n";

  if (isset($db32[$l])) {
    //    echo "already in DB: $l\n";
    continue;
  }

  fw_addIP('smtpbl', $l);
  $db32[$l] = true;
  //  break;
 }
fclose($fp);

iptc_commit();

function fw_addIP($name, $ip) {
  global $db8, $db16, $db24;
  //  echo "adding ip $ip\n";
  $ip_t = explode('.', $ip);
  $subnet8 = $ip_t[0];
  $subnet16 = $ip_t[0].'.'.$ip_t[1];
  $subnet24 = $ip_t[0].'.'.$ip_t[1].'.'.$ip_t[2];

  $chain = s('%s-list', $name);
  chain_create($chain);
  //  ipt_flush_entries($chain);

  chain_create(s("smtpbl-list-%s-8", $subnet8));
  //  ipt_flush_entries(s("smtpbl-list-%s-8", $subnet8));

  if (! isset($db8[$subnet8])) {
    rule_create($chain, s('%s.0.0.0/8', $subnet8), s('smtpbl-list-%s-8', $subnet8));
    $db8[$subnet8] = true;
  }

  chain_create(s("smtpbl-list-%s-16", $subnet16));
  //  ipt_flush_entries(s("smtpbl-list-%s-16", $subnet16));
  if (! isset($db16[$subnet16])) {
    rule_create(s('smtpbl-list-%s-8', $subnet8), s('%s.0.0/16', $subnet16),
		s('smtpbl-list-%s-16', $subnet16));
    $db16[$subnet16] = true;
  }

  chain_create(s("smtpbl-list-%s-24", $subnet24));
  //  ipt_flush_entries(s("smtpbl-list-%s-24", $subnet24));
  if (! isset($db24[$subnet24])) {
    rule_create(s('smtpbl-list-%s-16', $subnet16), s('%s.0/24', $subnet24),
		s('smtpbl-list-%s-24', $subnet24));
    $db24[$subnet24] = true;
  }
  //  print_r($db24);

  chain_create('chez_leon');
  rule_create(s('smtpbl-list-%s-24', $subnet24), $ip, 'chez_leon');

  return true;
  /* Delete everything */
  delete(s('smtpbl-list-%s-24', $subnet24), $ip, 'chez_leon');

  delete(s('smtpbl-list-%s-16', $subnet16), s('%s.0/24', $subnet24),
              s('smtpbl-list-%s-24', $subnet24));
  ipt_delete_chain(s("smtpbl-list-%s-24", $subnet24));

  delete(s('smtpbl-list-%s-8', $subnet8), s('%s.0.0/16', $subnet16),
              s('smtpbl-list-%s-16', $subnet16));
  ipt_delete_chain(s("smtpbl-list-%s-16", $subnet16));

  delete($chain, s('%s.0.0.0/8', $subnet8), s('smtpbl-list-%s-8', $subnet8));
  ipt_delete_chain(s("smtpbl-list-%s-8", $subnet8));
  ipt_delete_chain($chain);
  ipt_delete_chain('chez_leon');
}
function s($format, $value) {
  return sprintf($format, $value);
}
function chain_create($chain) {
  if (! iptc_is_chain($chain)) {
    iptc_create_chain($chain);
  }
}
function rule_create($chain, $source, $target) {
  if (! rule_exists($chain, $source, $target)) {
    //    ipt_insert_rule($chain, $source, $target);
    ipt_do_command(sprintf('-I %s -s %s -j %s', $chain, $source, $target));
  }
}

function delete($chain, $source, $target) {
  ipt_do_command(sprintf('-D %s -s %s -j %s', $chain, $source, $target));
}

function rule_exists($chain, $source, $target) {
  return false;
}
