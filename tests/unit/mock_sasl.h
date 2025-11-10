/*
 * Mock SASL Framework for Unit Testing
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#ifndef MOCK_SASL_H
#define MOCK_SASL_H

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global test counters */
extern int tests_total;
extern int tests_passed;
extern int tests_failed;

/* Mock configuration storage */
typedef struct mock_config_entry {
    char *plugin_name;
    char *key;
    char *value;
    struct mock_config_entry *next;
} mock_config_entry_t;

extern mock_config_entry_t *mock_config_head;

#define MOCK_CONFIG_MAX 32

/* Mock memory tracking */
extern int mock_malloc_count;
extern int mock_free_count;

/* Mock function declarations */
void mock_config_clear(void);
void mock_config_set(const char *section, const char *key, const char *value);
char *mock_config_get(const char *key);
int mock_getopt(void *context, const char *plugin_name, const char *option,
                const char **result, unsigned *len);
void *mock_malloc(size_t size);
void mock_free(void *ptr);
void mock_reset_malloc_counts(void);
int mock_get_malloc_count(void);
int mock_get_free_count(void);
void mock_seterror(sasl_conn_t *conn, unsigned flags, const char *fmt, ...);
void mock_log(sasl_conn_t *conn, int level, const char *fmt, ...);

/* Forward declaration to match SASL's usage */
struct sasl_conn;
typedef struct sasl_conn sasl_conn_t;

/* SASL constants for testing */
#ifndef SASL_SEC_NOPLAINTEXT
#define SASL_SEC_NOPLAINTEXT 0x0001
#endif
#ifndef SASL_SEC_NOACTIVE
#define SASL_SEC_NOACTIVE 0x0002
#endif
#ifndef SASL_SEC_NODICTIONARY
#define SASL_SEC_NODICTIONARY 0x0004
#endif
#ifndef SASL_OK
#define SASL_OK 0
#endif
#ifndef SASL_FAIL
#define SASL_FAIL -1
#endif
#ifndef SASL_NOMEM
#define SASL_NOMEM -2
#endif
#ifndef SASL_BADPARAM
#define SASL_BADPARAM -3
#endif
#ifndef SASL_BADAUTH
#define SASL_BADAUTH -4
#endif
#ifndef SASL_CONTINUE
#define SASL_CONTINUE 1
#endif

#endif /* MOCK_SASL_H */
