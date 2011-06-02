/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2008 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/*
 * Helpful documentation: http://www.linuxdoc.org/HOWTO/Querying-libiptc-HOWTO/mfunction.html
 * http://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-4.html
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_iptables.h"

/* Include libiptc */
#include <netinet/ip.h>
#include <libiptc/libiptc.h>
/* Include xtables */
#include <xtables.h>

/** Collect version from netfilter bundle */
#include "iptables/include/iptables/internal.h"

/** Get some external variables */
#include "iptables/include/iptables.h"


/* If you declare any globals in php_iptables.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(iptables)
*/

/* True global resources - no need for thread safety here */
static int le_iptables;

/* {{{ iptables_functions[]
 *
 * Every user visible function must have an entry in iptables_functions[].
 */
const zend_function_entry iptables_functions[] = {
	PHP_FE(ipt_do_command, NULL)
	PHP_FE(ipt_insert_rule, NULL)
	PHP_FE(ipt_is_chain, NULL)
	PHP_FE(ipt_get_chains, NULL)
	PHP_FE(ipt_get_policy, NULL)
	PHP_FE(ipt_set_policy, NULL)
	PHP_FE(ipt_delete_chain, NULL)
	PHP_FE(ipt_create_chain, NULL)
	PHP_FE(suck_my_balls, NULL)
	PHP_FE(confirm_iptables_compiled,	NULL)		/* For testing, remove later. */
	{NULL, NULL, NULL}	/* Must be the last line in iptables_functions[] */
};
/* }}} */

/* {{{ iptables_module_entry
 */
zend_module_entry iptables_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"iptables",
	iptables_functions,
	PHP_MINIT(iptables),
	PHP_MSHUTDOWN(iptables),
	PHP_RINIT(iptables),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(iptables),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(iptables),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1", /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_IPTABLES
ZEND_GET_MODULE(iptables)
#endif

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("iptables.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_iptables_globals, iptables_globals)
    STD_PHP_INI_ENTRY("iptables.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_iptables_globals, iptables_globals)
PHP_INI_END()
*/
/* }}} */

/* {{{ php_iptables_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_iptables_init_globals(zend_iptables_globals *iptables_globals)
{
	iptables_globals->global_value = 0;
	iptables_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(iptables)
{
	/* If you have INI entries, uncomment these lines 
	REGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(iptables)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(iptables)
{
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(iptables)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(iptables)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "iptables support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/** Utility functions */
int check_root()
{
	if (getuid() != 0) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "you need to be root");
		return 0;
	}
	return 1;
}

struct iptc_handle *php_iptc_init(const char *table)
{
}

int php_iptc_commit(struct iptc_handle *handle)
{
	int ret;
	ret = iptc_commit(handle);
	if (!ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "commit error");
	}
	return ret;
}


/** Used to set the global table / handle to the rest of the functions 
	Default to "filter"
*/
PHP_FUNCTION(ipt_set_table)
{
	const char *table = "filter";
}

PHP_FUNCTION(ipt_insert_rule)
{
	unsigned int i;
	struct iptc_handle *handle = NULL;
	const char *table = "filter";
	//	struct ipt_entry *e = NULL;
	const struct ipt_entry *e;
	char *chain, *source, *target;
	int chain_len, source_len, target_len;
	int ret;
	unsigned int nsaddrs = 0;
	struct in_addr *saddrs = NULL, *smasks = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", 
							  &chain, &chain_len, &source, &source_len, 
							  &target, &target_len) == FAILURE) {
		return;
	}

	check_root();
	handle = iptc_init(table);
	if (handle == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "couldnt create handle");
		RETURN_FALSE;
	}

	php_printf("+i %30s %20s %30s\n", chain, source, target);
	xtables_ipparse_multiple(source, &saddrs, &smasks, &nsaddrs);
   	php_printf("result: %d addresses\n", nsaddrs);
	if (nsaddrs != 1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Found too few or many address(es): %d",
						 nsaddrs);
		return;
	}


	//	e = generate_entry();
	//	php_printf("debug 1\n");
	//	e->ip.src.s_addr = saddrs[0].s_addr;
	//	e->ip.smsk.s_addr = smasks[0].s_addr;
	//	php_printf("debug 2\n");
	ret = 1;
	//	ret = iptc_insert_entry(chain, e, -1, handle);
	if (! ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "cannot insert rule: %s (%d)", iptc_strerror(errno), errno);
	}

	php_iptc_commit(handle);
	RETURN_BOOL(ret);
}

/** Ripped from http://pthreads.blogspot.com/2008/10/explode-function-in-c.html */
char **explode(char *string, char separator, int *arraySize)
{
	int start = 0, i, k = 0, count = 2;
	char **strarr;
	for (i = 0; string[i] != '\0'; i++){
		/* Number of elements in the array */
		if (string[i] == separator){
			count++;
		}
	}
	arraySize[0] = count;
	//	arraySize[0] = count-1;
	/* count is at least 2 to make room for the entire string
	 * and the ending NULL */
	strarr = calloc(count, sizeof(char*));
	i = 0;
	strarr[i] = strdup("iptables");
	i++;
	while (*string != '\0') {
		if (*string == separator) {
			strarr[i] = calloc(k - start + 2,sizeof(char));
			strncpy(strarr[i], string - k + start, k - start);
			strarr[i][k - start + 1] = '\0'; /* ensure null termination */
			start = k;
			start++;
			i++;
		}
		string++;
		k++;
	}
	/* copy the last part of the string after the last separator */
	strarr[i] = calloc(k - start + 1,sizeof(char));
	strncpy(strarr[i], string - k + start, k - start);
	strarr[++i] = NULL;
 
	return strarr;
}


/** do_command4() in 1.4.11 , do_command() in 1.4.4 */
PHP_FUNCTION(ipt_do_command)
{
	struct iptc_handle *handle = NULL;
	char *table = "filter";
	const char *program_name = "iptables";
	int ret, argc;
	char **argv;

	/** Arguments */
	char *command;
	int command_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &command, &command_len) == FAILURE) {
		return;
	}

	check_root();
	handle = iptc_init(table);
	if (handle == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "couldn't create handle: %s (%d)", iptc_strerror(errno), errno);
		RETURN_FALSE;
	}

	/** Trying to initialize the shit */
	iptables_globals.program_name = "iptables";
	ret = xtables_init_all(&iptables_globals, NFPROTO_IPV4);


	/** Parsing the command */
	php_printf("executing command: %s\n", command);
	argv = explode(command, ' ', &argc);
	unsigned int i;
	for (i = 0; argv[i]; i++) {
		php_printf("argv[%d]: %s (%d)\n", i, argv[i], argc);
	}

	//	php_printf("i: %d\n", i);
	if (! strcmp(IPTABLES_VERSION, "1.4.11")) {
		php_printf("using do_command4() version: %s\n", IPTABLES_VERSION);
		ret = do_command4(argc, argv, &table, &handle);
	} else if (! strcmp(IPTABLES_VERSION, "1.4.4")) {
		php_printf("using do_command() version: %s\n", IPTABLES_VERSION);
		ret = do_command(argc, argv, &table, &handle);
	}
	if (! ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "%s (%d)", iptc_strerror(errno), errno);	
	} else {
		php_iptc_commit(handle);
	}
	RETURN_BOOL(ret);
}

PHP_FUNCTION(ipt_is_chain)
{
	struct iptc_handle *handle = NULL;
	const char *table = "filter";
	char *chain;
	int chain_len;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &chain, &chain_len) == FAILURE) {
		return;
	}

	check_root();
	handle = iptc_init(table);
	if (handle == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "couldnt create handle");
		RETURN_FALSE;
	}

	ret = iptc_is_chain(chain, handle);
	RETURN_BOOL(ret);
}

PHP_FUNCTION(ipt_get_chains)
{
	struct iptc_handle *handle = NULL;
	const char *table = "filter";
	char *chain;
   	check_root();
	handle = iptc_init(table);
	if (handle == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "couldnt create handle");
		RETURN_FALSE;
	}

	/*
	chain = iptc_first_chain(handle);
	php_printf("chain found: %s\n", chain);
	while ((chain = iptc_next_chain(handle)) != NULL) {
		php_printf("chain found: %s\n", chain);
	}
	*/
	RETURN_TRUE;
}

PHP_FUNCTION(ipt_delete_chain)
{
	struct iptc_handle *handle = NULL;
	const char *table = "filter";
	char *chain;
	int chain_len;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &chain, &chain_len) == FAILURE) {
		return;
	}

	check_root();
	handle = iptc_init(table);
	if (handle == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "couldnt create handle");
		RETURN_FALSE;
	}

   	ret = iptc_delete_chain(chain, handle);
	if (!ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "couldn't delete chain %s: %s (%d)", chain, iptc_strerror(errno), errno);
	}

	php_iptc_commit(handle);
	RETURN_BOOL(ret);
}

PHP_FUNCTION(ipt_create_chain)
{
	struct iptc_handle *handle = NULL;
	const char *table = "filter";
	char *chain;
	int chain_len;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &chain, &chain_len) == FAILURE) {
		return;
	}

	check_root();
	handle = iptc_init(table);
	if (handle == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "couldnt create handle");
		RETURN_FALSE;
	}

	/*	
	php_printf("attempting to create a new chain: %s (%d) (errno: %d)\n",
			   chain, chain_len, errno);
	*/
	/** ipt_chainlabel is a char[32] */
   	ret = iptc_create_chain(chain, handle);
	if (!ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "couldn't create chain %s: %s (%d)", chain, iptc_strerror(errno), errno);
	}

	php_iptc_commit(handle);
	RETURN_BOOL(ret);
}

PHP_FUNCTION(ipt_get_policy)
{
	struct ipt_counters counters;
	struct iptc_handle *handle = NULL;
	const char *pol;
	char *name;
	int name_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
							  &name, &name_len) == FAILURE) {
		//		php_error_docref(NULL TSRMLS_CC, E_WARNING, "expects a chain name");
		return;
	}

	check_root();

	const char *table = "filter";
	//	php_printf("table: %s\n", table);
	handle = iptc_init(table);
	if (handle == NULL) { // when not root, it happens when segfaults later at get_policy()
		php_printf("handle is null, exiting");
		return;
	}
	//	php_printf("checking policy for chain %s\n", name);
	pol = iptc_get_policy(name, &counters, handle);
	//	php_printf("policy= %s\n", pol);
	RETURN_STRING(pol, 1);
}


/** NON WORKING SO FAR */
PHP_FUNCTION(ipt_set_policy) 
{
	struct ipt_counters *new_counters = NULL;
	struct ipt_counters counters;
	struct iptc_handle *handle = NULL;
	char *chain;
	int chain_len;
	char *policy;
	int policy_len;
	int ret;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", 
							  &chain, &chain_len, &policy, &policy_len) == FAILURE) {
		return;
	}

	check_root();

	const char *table = "filter";
	handle = iptc_init(table);
	if (handle == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "needs to run as root");
		return;
	}
	//	iptc_get_policy(chain, &counters, handle);
	iptc_set_policy(chain, policy, new_counters, handle);

	ret = php_iptc_commit(handle);
	RETURN_BOOL(ret);
}

PHP_FUNCTION(suck_my_balls)
{
	char *name;
	int name_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
							  &name, &name_len) == FAILURE) {
		RETURN_FALSE;
	}
	php_printf("suck my balls %s!\n", name);
	RETURN_TRUE;
}


/* Remove the following function when you have succesfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_iptables_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(confirm_iptables_compiled)
{
	char *arg = NULL;
	int arg_len, len;
	char *strg;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &arg, &arg_len) == FAILURE) {
		return;
	}

	len = spprintf(&strg, 0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "iptables", arg);
	RETURN_STRINGL(strg, len, 0);
}
/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and 
   unfold functions in source code. See the corresponding marks just before 
   function definition, where the functions purpose is also documented. Please 
   follow this convention for the convenience of others editing your code.
*/


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
