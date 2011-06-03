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
 * Documentation (Netfilter):
 * http://www.linuxdoc.org/HOWTO/Querying-libiptc-HOWTO/mfunction.html
 * http://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-4.html
 *
 * Documentation (PHP extensions):
 * Extension Writing Part II: Parameters, Arrays, and ZVALs:
 * http://devzone.zend.com/node/view/id/1022
 *
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

/** Get some external variables (otherwise wont work) */
#include "iptables/include/iptables.h"

#define	DEFAULT_TABLE	"filter"

/* If you declare any globals in php_iptables.h uncomment this: */
ZEND_DECLARE_MODULE_GLOBALS(iptables2)


/* True global resources - no need for thread safety here */
static int le_iptables;

/* {{{ iptables_functions[]
 *
 * Every user visible function must have an entry in iptables_functions[].
 */
const zend_function_entry iptables_functions[] = {

	PHP_FE(iptc_get, NULL)
	PHP_FE(iptc_inc, NULL)

	PHP_FE(iptc_commit, NULL)
	PHP_FE(iptc_init, NULL)
	PHP_FE(iptc_free, NULL)
	PHP_FE(iptc_get_chains, NULL)
	PHP_FE(iptc_is_chain, NULL)
	PHP_FE(iptc_create_chain, NULL)
	PHP_FE(iptc_delete_chain, NULL)
	PHP_FE(iptc_flush_entries, NULL)

	PHP_FE(ipt_do_command, NULL)
	PHP_FE(ipt_insert_rule, NULL)
	PHP_FE(ipt_get_policy, NULL)
	PHP_FE(ipt_set_policy, NULL)

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
	IPTABLES_G(table) = DEFAULT_TABLE;
	IPTABLES_G(handle) = NULL;
	IPTABLES_G(counter) = 0;
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(iptables)
{
	struct iptc_handle *handle;

	handle = IPTABLES_G(handle);
	if (handle == NULL) {
		php_printf("handle is null\n");
	}
	if (handle != NULL) {
		iptc_free(handle);
	}

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


PHP_FUNCTION(iptc_get)
{
	//	php_iptc_init();
	//	php_printf("current counter: %ld\n", IPTABLES_G(counter));
	RETURN_LONG(IPTABLES_G(counter));
}
PHP_FUNCTION(iptc_inc)
{
	//	php_iptc_init();
	IPTABLES_G(counter) = IPTABLES_G(counter) + 1;
	//	php_printf("current counter: %ld\n", IPTABLES_G(counter));
}


/** Utility functions 
 ** Not used anymore, thanks to iptc_strerror() in php_iptc_init();
 */
int check_root()
{
	if (getuid() != 0) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "you need to be root");
		return 0;
	}
	return 1;
}


/*
** To be called at each and every function
*/
int php_iptc_init()
{
	char *table;
	struct iptc_handle *handle;

	handle = IPTABLES_G(handle);
	if (handle != NULL) {
		/* Handle already defined */
		return SUCCESS; 
	}

	table = IPTABLES_G(table); // missing an error check here...
	//	php_printf("fetched table name: %s\n", table);
	handle = iptc_init(table);
	if (! handle) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Cannot get a handle: %s (%d)",
						 iptc_strerror(errno), errno);
		return FAILURE;
	}
	/* Saving handle for future use */
	IPTABLES_G(handle) = handle;

	return SUCCESS;
}

PHP_FUNCTION(iptc_init)
{
	RETURN_BOOL(php_iptc_init());
}

PHP_FUNCTION(iptc_free)
{
	struct iptc_handle *handle;
	handle = IPTABLES_G(handle);
	php_printf("handle: %p\n", handle);
	if (handle != NULL) {
		iptc_free(handle);
	}
}

int php_iptc_commit()
{
	struct iptc_handle *handle;
	int ret;

	handle = IPTABLES_G(handle);
	if (handle == NULL) {
		return SUCCESS; /* Nothing to commit but no big deal */
	}

	if (! iptc_commit(handle)) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Cannot commit: %s (%d)",
						 iptc_strerror(errno), errno);
		return FAILURE;
	}

	/* Clean up */
	iptc_free(handle);
	IPTABLES_G(handle) = NULL;

	return SUCCESS;
}

PHP_FUNCTION(iptc_commit)
{
	RETURN_BOOL(php_iptc_commit());
}

/** Used to set the global table / handle to the rest of the functions 
	Default to "filter"
*/
PHP_FUNCTION(ipt_set_table)
{
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
	handle = create_handle(table);
	//	handle = iptc_init(table);
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

	//	php_iptc_commit(handle);
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
	strarr = ecalloc(count, sizeof(char*));
	i = 0;
	strarr[i] = strdup("iptables");
	i++;
	while (*string != '\0') {
		if (*string == separator) {
			strarr[i] = ecalloc(k - start + 2,sizeof(char));
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
	strarr[i] = ecalloc(k - start + 1,sizeof(char));
	strncpy(strarr[i], string - k + start, k - start);
	strarr[++i] = NULL;
 
	return strarr;
}


/** do_command4() in 1.4.11 , do_command() in 1.4.4 */
PHP_FUNCTION(ipt_do_command)
{
	struct iptc_handle *handle = NULL;
	const char *program_name = "iptables";
	char *table;
	int ret, argc;
	char **argv;

	/** Arguments */
	char *command;
	int command_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &command, &command_len) == FAILURE) {
		return;
	}

	php_iptc_init();
	handle = IPTABLES_G(handle);
	table = IPTABLES_G(table);

	/** Trying to initialize the shit */
	iptables_globals.program_name = "iptables";
	iptables_globals.program_version = IPTABLES_VERSION;
	ret = xtables_init_all(&iptables_globals, NFPROTO_IPV4);

	/** Parsing the command */
	//	php_printf("executing command: %s\n", command);
	argv = explode(command, ' ', &argc);
	/* DEBUG 
	unsigned int i;
	for (i = 0; argv[i]; i++) {
		php_printf("argv[%d]: %s (%d)\n", i, argv[i], argc);
	}
	*/

	if (! strcmp(IPTABLES_VERSION, "1.4.11")) {
		ret = do_command4(argc, argv, &table, &handle);
	} else if (! strcmp(IPTABLES_VERSION, "1.4.4")) {
		ret = do_command(argc, argv, &table, &handle);
	}
	if (! ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "%s (%d)", iptc_strerror(errno), errno);	
		//	} else {
		//		php_iptc_commit(handle);
		//		iptc_free(handle);
		//		handle = NULL;
	}
	RETURN_BOOL(ret);
}

PHP_FUNCTION(iptc_is_chain)
{
	struct iptc_handle *handle = NULL;
	char *chain;
	int chain_len;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &chain, &chain_len) == FAILURE) {
		return;
	}
	php_iptc_init();
	handle = IPTABLES_G(handle);

	ret = iptc_is_chain(chain, handle);
	RETURN_BOOL(ret);
}

PHP_FUNCTION(iptc_get_chains)
{
	struct iptc_handle *handle = NULL;
	const char *chain;
	int refs;
	zval *chains;

	php_iptc_init();
	handle = IPTABLES_G(handle);

	ALLOC_INIT_ZVAL(chains);
	array_init(chains);
	for (chain = iptc_first_chain(handle); 
		 chain != NULL && iptc_get_references(&refs, chain, handle); 
		 chain = iptc_next_chain(handle)) {
		//		php_printf("chain found: %s (%d references)\n", chain, refs);
		add_next_index_string(chains, chain, 1);
		if (refs == 0) {
			//			php_printf("deleting empty chain: %s ..\n", chain);
			//			iptc_delete_chain(chain, handle);
		}
	}
	//	php_iptc_commit(handle);

	RETURN_ZVAL(chains, 1, 0);
}

PHP_FUNCTION(iptc_flush_entries)
{
	struct iptc_handle *handle = NULL;
	char *chain;
	int chain_len;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &chain, &chain_len) == FAILURE) {
		return;
	}

	php_iptc_init();
	handle = IPTABLES_G(handle);

   	ret = iptc_flush_entries(chain, handle);
	if (!ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "couldn't flush entries for chain %s: %s (%d)", 
						 chain, iptc_strerror(errno), errno);
	}
	//	php_iptc_commit(handle);
	RETURN_BOOL(ret);
}

PHP_FUNCTION(iptc_delete_chain)
{
	struct iptc_handle *handle = NULL;
	const char *table = "filter";
	char *chain;
	int chain_len;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &chain, &chain_len) == FAILURE) {
		return;
	}

	php_iptc_init();
	handle = IPTABLES_G(handle);

   	ret = iptc_delete_chain(chain, handle);
	if (!ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "couldn't delete chain %s: %s (%d)", chain, iptc_strerror(errno), errno);
	}

	//	php_iptc_commit(handle);
	RETURN_BOOL(ret);
}

PHP_FUNCTION(iptc_create_chain)
{
	struct iptc_handle *handle = NULL;
	const char *table = "filter";
	char *chain;
	int chain_len;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &chain, &chain_len) == FAILURE) {
		return;
	}

	php_iptc_init();
	handle = IPTABLES_G(handle);

	//	php_printf("attempting to create a new chain: %s\n", chain);

	/** ipt_chainlabel is a char[32] */
   	ret = iptc_create_chain(chain, handle);
	if (!ret) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, 
						 "couldn't create chain %s: %s (%d)", chain, iptc_strerror(errno), errno);
	}

	//	php_iptc_commit(handle);
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
	//	iptc_free(handle); // test
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

	//	ret = php_iptc_commit(handle);
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
