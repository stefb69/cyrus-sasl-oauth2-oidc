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

/* Helper function to load configuration from a fallback file */
static int oauth2_load_fallback_config(oauth2_config_t *config, const sasl_utils_t *utils, const char *filepath) {
    FILE *fp;
    char line[1024];
    char *discovery_url = NULL;
    char *issuer = NULL;
    char *client_id = NULL;
    char *audience = NULL;
    
    fp = fopen(filepath, "r");
    if (!fp) {
        OAUTH2_LOG_DEBUG(utils, "Fallback config file not found: %s", filepath);
        return OAUTH2_CONFIG_NOT_FOUND;
    }
    
    OAUTH2_LOG_DEBUG(utils, "Loading fallback configuration from: %s", filepath);
    
    /* Read and parse the file line by line */
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Strip newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0' || line[0] == '\n') {
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
        
        char *key_end = key + strlen(key) - 1;
        while (key_end > key && (*key_end == ' ' || *key_end == '\t')) {
            *key_end = '\0';
            key_end--;
        }
        
        char *value_end = value + strlen(value) - 1;
        while (value_end > value && (*value_end == ' ' || *value_end == '\t')) {
            *value_end = '\0';
            value_end--;
        }
        
        /* Store values */
        if (strcmp(key, "oauth2_discovery_url") == 0 && strlen(value) > 0) {
            discovery_url = strdup(value);
        } else if (strcmp(key, "oauth2_issuer") == 0 && strlen(value) > 0) {
            issuer = strdup(value);
        } else if (strcmp(key, "oauth2_client_id") == 0 && strlen(value) > 0) {
            client_id = strdup(value);
        } else if (strcmp(key, "oauth2_audience") == 0 && strlen(value) > 0) {
            audience = strdup(value);
        }
    }
    
    fclose(fp);
    
    /* Apply loaded configuration if we have essential values */
    if (discovery_url || issuer) {
        if (discovery_url) {
            config->discovery_urls = oauth2_parse_string_list(discovery_url, &config->discovery_urls_count);
            free(discovery_url);
        } else if (issuer) {
            config->issuers = oauth2_parse_string_list(issuer, &config->issuers_count);
            free(issuer);
        }
        
        if (client_id) {
            config->client_id = client_id;  /* Keep the strdup'd pointer */
            config->client_id_allocated = 1;  /* Mark as allocated so we can free it later */
        }
        
        if (audience) {
            config->audiences = oauth2_parse_string_list(audience, &config->audiences_count);
            free(audience);
        }
        
        OAUTH2_LOG_INFO(utils, "Loaded OAuth2 configuration from fallback file: %s", filepath);
        return SASL_OK;
    }
    
    /* Cleanup if we didn't use the values */
    if (discovery_url) free(discovery_url);
    if (issuer) free(issuer);
    if (client_id) free(client_id);
    if (audience) free(audience);
    
    OAUTH2_LOG_DEBUG(utils, "Fallback config file exists but contains no valid OAuth2 configuration");
    return OAUTH2_CONFIG_NOT_FOUND;
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
        return (strcasecmp(value, "yes") == 0 || 
                strcasecmp(value, "true") == 0 || 
                strcasecmp(value, "1") == 0) ? 1 : 0;
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
    
    /* NOTE: Other simple string configurations are pointers to SASL internal data - do NOT free them */
    /* config->client_secret, scope, user_claim point to getopt() results */
    
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
    
    /* Load client credentials - only required if configuration is present */
    /* Don't override if already set from fallback config */
    if (!config->client_id) {
        config->client_id = (char*)oauth2_config_get_string(utils, OAUTH2_CONF_CLIENT_ID, NULL);
    }
    if (!config->client_secret) {
        config->client_secret = (char*)oauth2_config_get_string(utils, OAUTH2_CONF_CLIENT_SECRET, NULL);
    }
    
    /* Only validate client_id if configuration is present */
    if (config->configured && !config->client_id) {
        OAUTH2_LOG_ERR(utils, "%s must be configured", OAUTH2_CONF_CLIENT_ID);
        return SASL_FAIL;
    }
    
    /* Load token validation settings - support multiple audiences */
    const char *audiences_str = oauth2_config_get_string(utils, OAUTH2_CONF_AUDIENCES, NULL);
    const char *audience_str = oauth2_config_get_string(utils, OAUTH2_CONF_AUDIENCE, NULL);
    
    /* Log key configuration loaded */
    OAUTH2_LOG_DEBUG(utils, "Client ID configured: %s", config->client_id ? config->client_id : "N/A");
    
    /* Validate exclusive configuration for audiences */
    if (audiences_str && audience_str) {
        OAUTH2_LOG_ERR(utils, "Cannot configure both %s and %s - use only one form", 
                      OAUTH2_CONF_AUDIENCES, OAUTH2_CONF_AUDIENCE);
        return SASL_FAIL;
    }
    
    /* Parse audiences (priority: plural form, then singular) */
    if (audiences_str) {
        config->audiences = oauth2_parse_string_list(audiences_str, &config->audiences_count);
    } else if (audience_str) {
        config->audiences = oauth2_parse_string_list(audience_str, &config->audiences_count);
    }
    
    config->scope = (char*)oauth2_config_get_string(utils, OAUTH2_CONF_SCOPE, OAUTH2_DEFAULT_SCOPE);
    config->user_claim = (char*)oauth2_config_get_string(utils, OAUTH2_CONF_USER_CLAIM, OAUTH2_DEFAULT_USER_CLAIM);
    config->verify_signature = oauth2_config_get_bool(utils, OAUTH2_CONF_VERIFY_SIGNATURE, OAUTH2_DEFAULT_VERIFY_SIGNATURE);
    
    /* Load network settings */
    config->ssl_verify = oauth2_config_get_bool(utils, OAUTH2_CONF_SSL_VERIFY, OAUTH2_DEFAULT_SSL_VERIFY);
    config->timeout = oauth2_config_get_int(utils, OAUTH2_CONF_TIMEOUT, OAUTH2_DEFAULT_TIMEOUT);
    config->debug = oauth2_config_get_bool(utils, OAUTH2_CONF_DEBUG, OAUTH2_DEFAULT_DEBUG);
    
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