/*
 * Mock SASL Framework Implementation for Unit Testing
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "mock_sasl.h"
#include "test_framework.h"
#include <string.h>
#include <stdio.h>

/* Mock configuration storage - using linked list like in test_framework.h */
mock_config_entry_t *mock_config_head = NULL;

/* Mock memory tracking */
int mock_malloc_count = 0;
int mock_free_count = 0;

/* Clear all mock configuration */
void mock_config_clear(void) {
    mock_config_entry_t *current = mock_config_head;
    while (current != NULL) {
        mock_config_entry_t *next = current->next;
        if (current->plugin_name) free(current->plugin_name);
        free(current->key);
        free(current->value);
        free(current);
        current = next;
    }
    mock_config_head = NULL;
}

/* Set a mock configuration value */
void mock_config_set(const char *plugin_name, const char *key, const char *value) {
    mock_config_entry_t *entry = (mock_config_entry_t *)malloc(sizeof(mock_config_entry_t));
    if (!entry) return;
    
    entry->plugin_name = plugin_name ? strdup(plugin_name) : NULL;
    entry->key = strdup(key);
    entry->value = strdup(value);
    entry->next = mock_config_head;
    mock_config_head = entry;
}

/* Get a mock configuration value */
char *mock_config_get(const char *key) {
    mock_config_entry_t *current = mock_config_head;
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            return current->value;
        }
        current = current->next;
    }
    return NULL;
}

/* Mock getopt function */
int mock_getopt(void *context, const char *plugin_name, const char *option,
                const char **result, unsigned *len) {
    mock_config_entry_t *current = mock_config_head;
    while (current != NULL) {
        /* Handle plugin_name matching */
        int plugin_match = (plugin_name == NULL && current->plugin_name == NULL) ||
                          (plugin_name != NULL && current->plugin_name != NULL && 
                           strcmp(current->plugin_name, plugin_name) == 0);
        
        if (plugin_match && strcmp(current->key, option) == 0) {
            *result = current->value;
            if (len) *len = strlen(current->value);
            return SASL_OK;
        }
        current = current->next;
    }
    
    *result = NULL;
    if (len) *len = 0;
    return SASL_FAIL;
}

/* Mock malloc function with tracking */
void *mock_malloc(size_t size) {
    mock_malloc_count++;
    return malloc(size);
}

/* Mock free function with tracking */
void mock_free(void *ptr) {
    if (ptr) {
        mock_free_count++;
        free(ptr);
    }
}

/* Reset memory tracking counters */
void mock_reset_malloc_counts(void) {
    mock_malloc_count = 0;
    mock_free_count = 0;
}

/* Get malloc count */
int mock_get_malloc_count(void) {
    return mock_malloc_count;
}

/* Get free count */
int mock_get_free_count(void) {
    return mock_free_count;
}

/* Mock seterror function with correct SASL signature */
void mock_seterror(sasl_conn_t *conn, unsigned flags, const char *fmt, ...) {
    /* For testing, we just ignore error setting */
    (void)conn;
    (void)flags;
    (void)fmt;
    /* No actual error handling in tests */
}

/* Mock log function with correct SASL signature */
void mock_log(sasl_conn_t *conn, int level, const char *fmt, ...) {
    /* For testing, we just ignore logging */
    (void)conn;
    (void)level;
    (void)fmt;
}
