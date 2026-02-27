/*
 * OAuth2/OIDC SASL Plugin - Configuration Management
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "oauth2_plugin.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

/* For strdup function */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Include for file operations */
#include <stdio.h>

/* Secure memory clearing - prevents compiler from optimizing away the zeroing */
static void oauth2_secure_clear(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/* Parse a boolean value string (yes/true/1 → 1, anything else → 0) */
static int oauth2_parse_bool_value(const char *value) {
    return (strcasecmp(value, "yes") == 0 ||
            strcasecmp(value, "true") == 0 ||
            strcasecmp(value, "1") == 0) ? 1 : 0;
}

/* Helper function to load configuration from a fallback file.
 * This supports applications like Postfix that don't pass plugin-specific
 * options through SASL getopt. All settings from the fallback file act as
 * defaults that can be overridden by SASL getopt values. */
static int oauth2_load_fallback_config(oauth2_config_t *config, const sasl_utils_t *utils, const char *filepath) {
    FILE *fp;
    char line[1024];

    /* Singular form values */
    char *discovery_url = NULL;
    char *issuer = NULL;
    char *client_id = NULL;
    char *audience = NULL;

    /* Plural form values */
    char *discovery_urls = NULL;
    char *issuers = NULL;
    char *audiences = NULL;

    /* Other settings */
    char *client_secret = NULL;
    char *scope = NULL;
    char *user_claim = NULL;
    char *verify_signature = NULL;
    char *ssl_verify = NULL;
    char *timeout_str = NULL;
    char *debug_str = NULL;

    fp = fopen(filepath, "r");
    if (!fp) {
        OAUTH2_LOG_DEBUG(utils, "Fallback config file not found: %s", filepath);
        return OAUTH2_CONFIG_NOT_FOUND;
    }

    OAUTH2_LOG_DEBUG(utils, "Loading fallback configuration from: %s", filepath);

    /* Read and parse the file line by line */
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Strip newline and carriage return */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        /* Parse key: value pairs */
        char *colon = strchr(line, ':');
        if (!colon) {
            continue;
        }

        *colon = '\0';
        char *key = line;
        char *value = colon + 1;

        /* Trim leading/trailing whitespace from key and value */
        while (*key == ' ' || *key == '\t') key++;
        while (*value == ' ' || *value == '\t') value++;

        char *end = key + strlen(key) - 1;
        while (end > key && (*end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        end = value + strlen(value) - 1;
        while (end > value && (*end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        if (strlen(value) == 0) continue;

        /* Store values - free previous if key appears multiple times */
        if (strcmp(key, OAUTH2_CONF_DISCOVERY_URL) == 0) {
            free(discovery_url);
            discovery_url = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_DISCOVERY_URLS) == 0) {
            free(discovery_urls);
            discovery_urls = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_ISSUER) == 0) {
            free(issuer);
            issuer = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_ISSUERS) == 0) {
            free(issuers);
            issuers = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_CLIENT_ID) == 0) {
            free(client_id);
            client_id = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_CLIENT_SECRET) == 0) {
            free(client_secret);
            client_secret = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_AUDIENCE) == 0) {
            free(audience);
            audience = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_AUDIENCES) == 0) {
            free(audiences);
            audiences = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_SCOPE) == 0) {
            free(scope);
            scope = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_USER_CLAIM) == 0) {
            free(user_claim);
            user_claim = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_VERIFY_SIGNATURE) == 0) {
            free(verify_signature);
            verify_signature = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_SSL_VERIFY) == 0) {
            free(ssl_verify);
            ssl_verify = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_TIMEOUT) == 0) {
            free(timeout_str);
            timeout_str = strdup(value);
        } else if (strcmp(key, OAUTH2_CONF_DEBUG) == 0) {
            free(debug_str);
            debug_str = strdup(value);
        }
    }

    fclose(fp);

    /* Plural forms take priority over singular forms */
    const char *effective_discovery = discovery_urls ? discovery_urls : discovery_url;
    const char *effective_issuer = issuers ? issuers : issuer;
    const char *effective_audience = audiences ? audiences : audience;

    /* We need at least discovery URL(s) or issuer(s) for valid config */
    if (!effective_discovery && !effective_issuer) {
        /* No valid configuration found - free everything */
        free(discovery_url); free(discovery_urls);
        free(issuer); free(issuers);
        free(client_id);
        if (client_secret) {
            oauth2_secure_clear(client_secret, strlen(client_secret));
            free(client_secret);
        }
        free(audience); free(audiences);
        free(scope); free(user_claim);
        free(verify_signature); free(ssl_verify);
        free(timeout_str); free(debug_str);

        OAUTH2_LOG_DEBUG(utils, "Fallback config file exists but contains no valid OAuth2 configuration");
        return OAUTH2_CONFIG_NOT_FOUND;
    }

    /* Apply discovery URLs */
    if (effective_discovery) {
        config->discovery_urls = oauth2_parse_string_list(effective_discovery, &config->discovery_urls_count);
    }

    /* Apply issuers */
    if (effective_issuer) {
        config->issuers = oauth2_parse_string_list(effective_issuer, &config->issuers_count);
    }

    /* Apply client credentials (ownership transferred to config) */
    if (client_id) {
        config->client_id = client_id;
        config->client_id_allocated = 1;
        client_id = NULL;  /* Prevent free below */
    }

    if (client_secret) {
        config->client_secret = client_secret;
        config->client_secret_allocated = 1;
        client_secret = NULL;
    }

    /* Apply audiences */
    if (effective_audience) {
        config->audiences = oauth2_parse_string_list(effective_audience, &config->audiences_count);
    }

    /* Apply other string settings (ownership transferred to config) */
    if (scope) {
        config->scope = scope;
        config->scope_allocated = 1;
        scope = NULL;
    }

    if (user_claim) {
        config->user_claim = user_claim;
        config->user_claim_allocated = 1;
        user_claim = NULL;
    }

    /* Apply bool/int settings */
    if (verify_signature) {
        config->verify_signature = oauth2_parse_bool_value(verify_signature);
    }

    if (ssl_verify) {
        config->ssl_verify = oauth2_parse_bool_value(ssl_verify);
    }

    if (timeout_str) {
        char *endptr;
        long val = strtol(timeout_str, &endptr, 10);
        if (endptr != timeout_str && *endptr == '\0' && val > 0 && val <= INT_MAX) {
            config->timeout = (int)val;
        } else {
            OAUTH2_LOG_WARN(utils, "Invalid timeout value in fallback config: %s", timeout_str);
        }
    }

    if (debug_str) {
        config->debug = oauth2_parse_bool_value(debug_str);
    }

    /* Free all temporary strings (NULLed ones were transferred to config) */
    free(discovery_url); free(discovery_urls);
    free(issuer); free(issuers);
    free(client_id);
    if (client_secret) {
        oauth2_secure_clear(client_secret, strlen(client_secret));
        free(client_secret);
    }
    free(audience); free(audiences);
    free(scope); free(user_claim);
    free(verify_signature); free(ssl_verify);
    free(timeout_str); free(debug_str);

    OAUTH2_LOG_INFO(utils, "Loaded OAuth2 configuration from fallback file: %s", filepath);
    return SASL_OK;
}

/* Utility function to parse space-separated string lists */
/*@null@*/ char **oauth2_parse_string_list(const char *input, int *count) {
    *count = 0;
    if (!input || strlen(input) == 0) {
        return NULL;
    }

    /* Count items first */
    char *temp = strdup(input);
    char *token = strtok(temp, " \t\n");
    int item_count = 0;
    while (token) {
        item_count++;
        token = strtok(NULL, " \t\n");
    }
    free(temp);

    if (item_count == 0) {
        return NULL;
    }

    /* Allocate array */
    char **list = malloc((item_count + 1) * sizeof(char*));
    if (!list) {
        return NULL;
    }

    /* Parse items */
    temp = strdup(input);
    token = strtok(temp, " \t\n");
    int i = 0;
    while ((token != NULL) && (i < item_count)) {
        list[i] = strdup(token);
        if (!list[i]) {
            /* Cleanup on error */
            for (int j = 0; j < i; j++) {
                free(list[j]);
            }
            free(list);
            free(temp);
            return NULL;
        }
        i++;
        token = strtok(NULL, " \t\n");
    }
    list[i] = NULL;
    free(temp);

    *count = item_count;
    return list;
}

void oauth2_free_string_list(char **list, int count) {
    if (!list) return;

    for (int i = 0; i < count; i++) {
        if (list[i]) {
            free(list[i]);
        }
    }
    free(list);
}

static const char *oauth2_config_get_string(const sasl_utils_t *utils,
                                           const char *key,
                                           const char *default_value) {
    const char *value;
    if (utils->getopt(utils->getopt_context, "oauth2", key, &value, NULL) == SASL_OK && value) {
        return value;  /* Return direct pointer - no strdup needed */
    }
    return default_value;
}

static int oauth2_config_get_int(const sasl_utils_t *utils,
                                const char *key,
                                int default_value) {
    const char *value;
    if (utils->getopt(utils->getopt_context, "oauth2", key, &value, NULL) == SASL_OK && value) {
        /* Secure integer parsing with validation */
        char *endptr;
        long parsed_value = strtol(value, &endptr, 10);

        /* Validate the conversion */
        if (endptr == value || *endptr != '\0') {
            /* Invalid number format */
            OAUTH2_LOG_WARN(utils, "Invalid integer value for %s: %s, using default %d",
                          key, value, default_value);
            return default_value;
        }

        /* Check for integer overflow/underflow */
        if (parsed_value > INT_MAX || parsed_value < INT_MIN) {
            OAUTH2_LOG_WARN(utils, "Integer value out of range for %s: %ld, using default %d",
                          key, parsed_value, default_value);
            return default_value;
        }

        return (int)parsed_value;
    }
    return default_value;
}

static int oauth2_config_get_bool(const sasl_utils_t *utils,
                                 const char *key,
                                 int default_value) {
    const char *value;
    if (utils->getopt(utils->getopt_context, "oauth2", key, &value, NULL) == SASL_OK && value) {
        return oauth2_parse_bool_value(value);
    }
    return default_value;
}

oauth2_config_t *oauth2_config_init(const sasl_utils_t *utils) {
    oauth2_config_t *config;

    config = utils->malloc(sizeof(oauth2_config_t));
    if (!config) {
        OAUTH2_LOG_ERR(utils, "Failed to allocate memory for configuration");
        return NULL;
    }

    memset(config, 0, sizeof(oauth2_config_t));

    /* Initialize int/bool fields to sentinel value (-1 = not set).
     * This allows fallback config values to be preserved when SASL getopt
     * has no value, while still detecting "not configured at all". */
    config->verify_signature = -1;
    config->ssl_verify = -1;
    config->timeout = -1;
    config->debug = -1;

    /* Initialize liboauth2 logging context with default level (will be adjusted after config load) */
    config->oauth2_log = oauth2_init(OAUTH2_LOG_WARN, NULL);
    if (!config->oauth2_log) {
        OAUTH2_LOG_ERR(utils, "Failed to initialize liboauth2 logging context");
        utils->free(config);
        return NULL;
    }

    return config;
}

void oauth2_config_free(oauth2_config_t *config) {
    if (!config) return;

    /* Free string list configurations */
    oauth2_free_string_list(config->discovery_urls, config->discovery_urls_count);
    oauth2_free_string_list(config->issuers, config->issuers_count);
    oauth2_free_string_list(config->audiences, config->audiences_count);

    /* Free client_id if it was allocated from fallback config */
    if (config->client_id_allocated && config->client_id) {
        free(config->client_id);
    }

    /* Free client_secret if allocated from fallback config (with secure clearing) */
    if (config->client_secret_allocated && config->client_secret) {
        oauth2_secure_clear(config->client_secret, strlen(config->client_secret));
        free(config->client_secret);
    }

    /* Free scope if allocated from fallback config */
    if (config->scope_allocated && config->scope) {
        free(config->scope);
    }

    /* Free user_claim if allocated from fallback config */
    if (config->user_claim_allocated && config->user_claim) {
        free(config->user_claim);
    }

    /* NOTE: Non-allocated string pointers (client_id, client_secret, scope, user_claim)
     * point to SASL internal data from getopt() or compiled-in defaults - do NOT free them */

    /* Cleanup liboauth2 logging context */
    if (config->oauth2_log) {
        oauth2_shutdown(config->oauth2_log);
    }

    free(config);
}

int oauth2_config_load(oauth2_config_t *config, const sasl_utils_t *utils) {
    if (!config || !utils) {
        return SASL_BADPARAM;
    }

    /* Loading OAuth2 configuration */

    /* Load OIDC Discovery settings - support multiple URLs/issuers */
    const char *discovery_urls_str = oauth2_config_get_string(utils, OAUTH2_CONF_DISCOVERY_URLS, NULL);
    const char *discovery_url_str = oauth2_config_get_string(utils, OAUTH2_CONF_DISCOVERY_URL, NULL);
    const char *issuers_str = oauth2_config_get_string(utils, OAUTH2_CONF_ISSUERS, NULL);
    const char *issuer_str = oauth2_config_get_string(utils, OAUTH2_CONF_ISSUER, NULL);

    /* Log configuration input summary */
    OAUTH2_LOG_DEBUG(utils, "Reading OAuth2 configuration from SASL");

    /* Validate exclusive configuration for discovery URLs */
    if (discovery_urls_str && discovery_url_str) {
        OAUTH2_LOG_ERR(utils, "Cannot configure both %s and %s - use only one form",
                      OAUTH2_CONF_DISCOVERY_URLS, OAUTH2_CONF_DISCOVERY_URL);
        return SASL_FAIL;
    }

    /* Parse discovery URLs (priority: plural form, then singular) */
    if (discovery_urls_str) {
        config->discovery_urls = oauth2_parse_string_list(discovery_urls_str, &config->discovery_urls_count);
    } else if (discovery_url_str) {
        config->discovery_urls = oauth2_parse_string_list(discovery_url_str, &config->discovery_urls_count);
    }

    /* Validate exclusive configuration for issuers */
    if (issuers_str && issuer_str) {
        OAUTH2_LOG_ERR(utils, "Cannot configure both %s and %s - use only one form",
                      OAUTH2_CONF_ISSUERS, OAUTH2_CONF_ISSUER);
        return SASL_FAIL;
    }

    /* Parse issuers (priority: plural form, then singular) */
    if (issuers_str) {
        config->issuers = oauth2_parse_string_list(issuers_str, &config->issuers_count);
    } else if (issuer_str) {
        config->issuers = oauth2_parse_string_list(issuer_str, &config->issuers_count);
    }

    /* Ensure we have at least one discovery URL or issuer */
    if (!config->discovery_urls && !config->issuers) {
        /* Check if any OAuth2-related configuration was attempted but failed */
        if (discovery_urls_str || discovery_url_str || issuers_str || issuer_str) {
            /* Configuration was attempted but invalid - this is an error */
            OAUTH2_LOG_ERR(utils, "Either %s/%s or %s/%s must be configured",
                          OAUTH2_CONF_DISCOVERY_URLS, OAUTH2_CONF_DISCOVERY_URL,
                          OAUTH2_CONF_ISSUERS, OAUTH2_CONF_ISSUER);
            return SASL_FAIL;
        } else {
            /* No OAuth2 configuration found in SASL config - try fallback config file */
            const char *fallback_path = oauth2_config_get_string(utils, OAUTH2_CONF_FALLBACK_CONFIG,
                                                                 OAUTH2_DEFAULT_FALLBACK_CONFIG);

            int fallback_result = oauth2_load_fallback_config(config, utils, fallback_path);
            if (fallback_result == SASL_OK) {
                /* Successfully loaded from fallback - continue with configuration */
                OAUTH2_LOG_INFO(utils, "Using fallback configuration from: %s", fallback_path);
            } else {
                /* No fallback configuration found either - plugin should remain inactive */
                OAUTH2_LOG_DEBUG(utils, "No OAuth2 configuration found - plugin will remain inactive");
                config->configured = 0;
                return OAUTH2_CONFIG_NOT_FOUND;
            }
        }
    }

    /* Mark configuration as present */
    config->configured = 1;

    /* If only issuers provided, construct discovery URLs */
    if (!config->discovery_urls && config->issuers) {
        config->discovery_urls = malloc(config->issuers_count * sizeof(char*));
        if (!config->discovery_urls) {
            OAUTH2_LOG_ERR(utils, "Failed to allocate memory for discovery URLs");
            return SASL_NOMEM;
        }

        config->discovery_urls_count = config->issuers_count;
        for (int i = 0; i < config->issuers_count; i++) {
            /* Ensure issuer doesn't end with slash */
            char *clean_issuer = strdup(config->issuers[i]);
            size_t issuer_len = strlen(clean_issuer);
            if (issuer_len > 0 && clean_issuer[issuer_len - 1] == '/') {
                clean_issuer[issuer_len - 1] = '\0';
            }

            size_t len = strlen(clean_issuer) + strlen("/.well-known/openid-configuration") + 1;
            config->discovery_urls[i] = malloc(len);
            if (!config->discovery_urls[i]) {
                OAUTH2_LOG_ERR(utils, "Failed to allocate memory for discovery URL %d", i);
                /* Cleanup partial allocation */
                for (int j = 0; j < i; j++) {
                    free(config->discovery_urls[j]);
                }
                free(config->discovery_urls);
                free(clean_issuer);
                return SASL_NOMEM;
            }

            snprintf(config->discovery_urls[i], len, "%s/.well-known/openid-configuration", clean_issuer);
            free(clean_issuer);
        }
    }

    /* Load client credentials - SASL getopt overrides fallback values */
    const char *getopt_client_id = oauth2_config_get_string(utils, OAUTH2_CONF_CLIENT_ID, NULL);
    if (getopt_client_id) {
        if (config->client_id_allocated && config->client_id) {
            free(config->client_id);
            config->client_id_allocated = 0;
        }
        config->client_id = (char*)getopt_client_id;
    }

    const char *getopt_client_secret = oauth2_config_get_string(utils, OAUTH2_CONF_CLIENT_SECRET, NULL);
    if (getopt_client_secret) {
        if (config->client_secret_allocated && config->client_secret) {
            oauth2_secure_clear(config->client_secret, strlen(config->client_secret));
            free(config->client_secret);
            config->client_secret_allocated = 0;
        }
        config->client_secret = (char*)getopt_client_secret;
    }

    /* Only validate client_id if configuration is present */
    if (config->configured && !config->client_id) {
        OAUTH2_LOG_ERR(utils, "%s must be configured", OAUTH2_CONF_CLIENT_ID);
        return SASL_FAIL;
    }

    /* Log key configuration loaded */
    OAUTH2_LOG_DEBUG(utils, "Client ID configured: %s", config->client_id ? config->client_id : "N/A");

    /* Load token validation settings - support multiple audiences.
     * SASL getopt overrides fallback audiences. */
    const char *audiences_str = oauth2_config_get_string(utils, OAUTH2_CONF_AUDIENCES, NULL);
    const char *audience_str = oauth2_config_get_string(utils, OAUTH2_CONF_AUDIENCE, NULL);

    /* Validate exclusive configuration for audiences */
    if (audiences_str && audience_str) {
        OAUTH2_LOG_ERR(utils, "Cannot configure both %s and %s - use only one form",
                      OAUTH2_CONF_AUDIENCES, OAUTH2_CONF_AUDIENCE);
        return SASL_FAIL;
    }

    /* Parse audiences - SASL getopt overrides fallback */
    if (audiences_str || audience_str) {
        if (config->audiences) {
            oauth2_free_string_list(config->audiences, config->audiences_count);
            config->audiences = NULL;
            config->audiences_count = 0;
        }
        if (audiences_str) {
            config->audiences = oauth2_parse_string_list(audiences_str, &config->audiences_count);
        } else {
            config->audiences = oauth2_parse_string_list(audience_str, &config->audiences_count);
        }
    }

    /* Scope - SASL getopt overrides fallback, compiled-in default as last resort */
    const char *getopt_scope = oauth2_config_get_string(utils, OAUTH2_CONF_SCOPE, NULL);
    if (getopt_scope) {
        if (config->scope_allocated && config->scope) {
            free(config->scope);
            config->scope_allocated = 0;
        }
        config->scope = (char*)getopt_scope;
    } else if (!config->scope) {
        config->scope = (char*)OAUTH2_DEFAULT_SCOPE;
    }

    /* User claim - SASL getopt overrides fallback, compiled-in default as last resort */
    const char *getopt_user_claim = oauth2_config_get_string(utils, OAUTH2_CONF_USER_CLAIM, NULL);
    if (getopt_user_claim) {
        if (config->user_claim_allocated && config->user_claim) {
            free(config->user_claim);
            config->user_claim_allocated = 0;
        }
        config->user_claim = (char*)getopt_user_claim;
    } else if (!config->user_claim) {
        config->user_claim = (char*)OAUTH2_DEFAULT_USER_CLAIM;
    }

    /* Bool/int settings - SASL getopt overrides fallback, compiled-in default as last resort.
     * We use -1 as sentinel to detect "not set by anyone yet". */
    int getopt_verify = oauth2_config_get_bool(utils, OAUTH2_CONF_VERIFY_SIGNATURE, -1);
    if (getopt_verify != -1) {
        config->verify_signature = getopt_verify;
    } else if (config->verify_signature == -1) {
        config->verify_signature = OAUTH2_DEFAULT_VERIFY_SIGNATURE;
    }

    int getopt_ssl = oauth2_config_get_bool(utils, OAUTH2_CONF_SSL_VERIFY, -1);
    if (getopt_ssl != -1) {
        config->ssl_verify = getopt_ssl;
    } else if (config->ssl_verify == -1) {
        config->ssl_verify = OAUTH2_DEFAULT_SSL_VERIFY;
    }

    int getopt_timeout = oauth2_config_get_int(utils, OAUTH2_CONF_TIMEOUT, -1);
    if (getopt_timeout != -1) {
        config->timeout = getopt_timeout;
    } else if (config->timeout == -1) {
        config->timeout = OAUTH2_DEFAULT_TIMEOUT;
    }

    int getopt_debug = oauth2_config_get_bool(utils, OAUTH2_CONF_DEBUG, -1);
    if (getopt_debug != -1) {
        config->debug = getopt_debug;
    } else if (config->debug == -1) {
        config->debug = OAUTH2_DEFAULT_DEBUG;
    }

    /* Adjust liboauth2 log level based on debug setting */
    if (config->oauth2_log) {
        oauth2_log_level_t log_level = config->debug ? OAUTH2_LOG_TRACE1 : OAUTH2_LOG_WARN;
        /* Change the log level of the default stderr sink */
        oauth2_log_sink_level_set(&oauth2_log_sink_stderr, log_level);
    }

    /* Network settings configured */
    OAUTH2_LOG_DEBUG(utils, "Network: SSL verify=%s, timeout=%ds, debug=%s",
                     config->ssl_verify ? "yes" : "no", config->timeout,
                     config->debug ? "yes" : "no");

    /* Log configuration summary */
    OAUTH2_LOG_INFO(utils, "OAuth2 configuration loaded: %d providers, %d audiences",
                   config->discovery_urls_count,
                   config->audiences_count);

    /* Log essential configuration at DEBUG level */
    OAUTH2_LOG_DEBUG(utils, "User claim: %s, signature verification: %s",
                     config->user_claim,
                     config->verify_signature ? "enabled" : "disabled");

    return SASL_OK;
}
