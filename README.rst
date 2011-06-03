=======================
Netfilter PHP extension
=======================

How to install:
---------------

Make sure you have the 2 netfilter libraries libxtables and libiptc, then::

1/ download the latest iptables package (so far working with 1.4.4 and 1.4.11)
2/ extract it in the same directory as this extension
3/ ln -s ./iptables-1.4.4 ./iptables
4/ phpize 
5/ ./configure --enable-iptables
6/ make
7/ enjoy your ./modules/iptables.so


-----------------
API documentation
-----------------

iptc_commit()
-------------

Iptables is working using transactions, once you want to commit changes done, just call iptc_commit()::

iptc_set_policy('FORWARD', 'DROP');
iptc_commit();



iptc_init()
iptc_free()

iptc_get_chains()
iptc_is_chain()
iptc_create_chain()
iptc_delete_chain()

iptc_flush_entries()
iptc_get_references()

iptc_get_policy()
iptc_set_policy()

iptc_do_command()
