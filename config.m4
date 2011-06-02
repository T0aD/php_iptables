dnl $Id$
dnl config.m4 for extension iptables

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

#PHP_ARG_WITH(iptables, for iptables support,
#Make sure that the comment is aligned:
#[  --with-iptables             Include iptables support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(iptables, whether to enable iptables support,
 Make sure that the comment is aligned:
 [  --enable-iptables           Enable iptables support])

if test "$PHP_IPTABLES" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-iptables -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/iptables.h"  # you most likely want to change this
  dnl if test -r $PHP_IPTABLES/$SEARCH_FOR; then # path given as parameter
  dnl   IPTABLES_DIR=$PHP_IPTABLES
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for iptables files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       IPTABLES_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$IPTABLES_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the iptables distribution])
  dnl fi

  dnl # --with-iptables -> add include path
  dnl PHP_ADD_INCLUDE($IPTABLES_DIR/include)

  dnl # --with-iptables -> check for lib and symbol presence
  dnl LIBNAME=iptc # you may want to change this
  dnl LIBSYMBOL=iptc # you most likely want to change this 

  dnl  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl	[
  dnl	PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $IPTABLES_DIR/lib, IPTABLES_SHARED_LIBADD)
  dnl	AC_DEFINE(HAVE_IPTABLESLIB,1,[ ])
  dnl	],[
  dnl  	AC_MSG_ERROR([wrong iptables lib version or lib not found])
  dnl  	],[
  dnl	-L$IPTABLES_DIR/lib -lm
  dnl	])
  PHP_ADD_LIBRARY(iptc,, IPTABLES_SHARED_LIBADD)
  PHP_ADD_LIBRARY(xtables,, IPTABLES_SHARED_LIBADD)
  PHP_SUBST(IPTABLES_SHARED_LIBADD)

  PHP_NEW_EXTENSION(iptables, iptables.c, $ext_shared)
fi
