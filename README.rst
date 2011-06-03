=======================
Netfilter PHP extension
=======================
-----------------------------
Or how to go insane with PHP
-----------------------------

How to install:
---------------

Make sure you have the 2 netfilter libraries libxtables and libiptc, then::

1. download the latest iptables package (so far working with 1.4.4 and 1.4.11)
2. extract it in the same directory as this extension
3. ln -s ./iptables-1.4.4 ./iptables
4. phpize 
5. ./configure --enable-iptables
6. make
7. enjoy your ./modules/iptables.so

How to use
----------

* No php.ini entries required
* Quick test: run using php -d enable_dl=on and dl('iptables.so'); inside your code

API documentation
-----------------

iptc_commit()
~~~~~~~~~~~~~

Commits changes performed

Iptables is working using transactions, once you want to commit changes done, just call iptc_commit()::

 iptc_set_policy('FORWARD', 'DROP');
 iptc_commit();


iptc_free()
~~~~~~~~~~~

No reason to call manually, move away people, nothing to see here!

iptc_init()
~~~~~~~~~~~

iptc_init((string) $table)

Selects a different table (the default one being "filter")::

 iptc_init('nat');
 iptc_create_chain('ucerta');
 iptc_commit();


iptc_get_chains()
~~~~~~~~~~~~~~~~~

* (array) $chains = iptc_get_chains();

Returns an array of existing chains::

 $chains = iptc_get_chains();
 foreach ($chains as $chain) {
   echo "Chain $chain was found (", iptc_get_references($chain), " references)\n";
 }

iptc_is_chain()
~~~~~~~~~~~~~~~

* (bool) $ret = iptc_is_chain((string) $chain)

Checks if a chain already exists::

 $chains = iptc_get_chains();
 foreach ($chains as $chain) {
  if (! iptc_is_chain($chain)) {
   echo "You'll never see this line\n";
  }
 }

iptc_builtin()
~~~~~~~~~~~~~~

* (bool) $ret = iptc_builtin((string) $chain)

Returns whether a chain is a builtin chain or not.::

 iptc_init('mangle');
 $chains = iptc_get_chains();
 foreach ($chains as $chain) {
   if (! iptc_builtin($chain)) {
     echo $chain, " ain't a builtin chain son!\n";
   }
 }

iptc_create_chain(), iptc_delete_chain()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* iptc_create_chain((string) $chain)
* iptc_delete_chain((string) $chain)

Creates or deletes a given chain (as long as it's not a builtin chain)::

 $chains = iptc_get_chains();
 foreach ($chains as $chain) {
  iptc_delete_chain($chain);
 }

iptc_flush_entries()
~~~~~~~~~~~~~~~~~~~~

Removes the entries of a chain

* iptc_flush_entries((string) $chain)

iptc_get_references()
~~~~~~~~~~~~~~~~~~~~~

Returns the number of references of a given chain

* (int) iptc_get_references((string) $chain)


iptc_get_policy(), iptc_set_policy()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sets or gets the policy for a builtin chain

* (string) $policy = iptc_get_policy((string) $chain)
* (int) ret = iptc_set_policy((string) $chain, (string) $policy))

iptc_do_command()
~~~~~~~~~~~~~~~~~

* iptc_do_command((string) $command)

Executes a command the classical way, like on the command line::

 iptc_do_command('-I INPUT -d 217.73.17.12 -j ACCEPT');
 iptc_do_command('-I INPUT -s 82.67.199.204 -j CHEZ_LEON');
 iptc_commit(); // commit changes

Note: might have issues if you insert quotes inside, as the parser simulates an explode() on spaces.


TODO
----

* A config.m4 that really fills its purpose in life
* Use a better parser than explode(' ', string) ?
* Publish at PECL.php.net and become a star!

