/*
 * OAuth2/OIDC SASL Plugin for Cyrus IMAP
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 * 
 * This plugin provides native OAuth2/OpenID Connect authentication
 * using liboauth2 for comprehensive OIDC support.
 * 
 * Features:
 * - Automatic OIDC Discovery
 * - JWT validation with signature verification
 * - JWKS caching and refresh
 * - Multi-provider support
 * - Configurable caching backends
 */

#ifndef OAUTH2_PLUGIN_H
#define OAUTH2_PLUGIN_H

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>
#include <oauth2/oauth2.h>
#include <oauth2/mem.h>
#include <oauth2/openidc.h>
#include "oauth2_types.h"

/* Plugin version and identification */
#define OAUTH2_PLUGIN_VERSION "1.0.0"
#define OAUTH2_PLUGIN_NAME "cyrus-sasl-oauth2-oidc"

/* Supported SASL mechanisms */
#define OAUTH2_MECH_XOAUTH2 "XOAUTH2"
#define OAUTH2_MECH_OAUTHBEARER "OAUTHBEARER"

/* Configuration keys */
#define OAUTH2_CONF_DISCOVERY_URL "oauth2_discovery_url"
#define OAUTH2_CONF_DISCOVERY_URLS "oauth2_discovery_urls"  /* Space-separated list */
#define OAUTH2_CONF_ISSUER "oauth2_issuer"
#define OAUTH2_CONF_ISSUERS "oauth2_issuers"  /* Space-separated list */
#define OAUTH2_CONF_CLIENT_ID "oauth2_client_id"
#define OAUTH2_CONF_CLIENT_SECRET "oauth2_client_secret"
#define OAUTH2_CONF_AUDIENCE "oauth2_audience"
#define OAUTH2_CONF_AUDIENCES "oauth2_audiences"  /* Space-separated list */
#define OAUTH2_CONF_SCOPE "oauth2_scope"
#define OAUTH2_CONF_USER_CLAIM "oauth2_user_claim"
#define OAUTH2_CONF_VERIFY_SIGNATURE "oauth2_verify_signature"
#define OAUTH2_CONF_SSL_VERIFY "oauth2_ssl_verify"
#define OAUTH2_CONF_TIMEOUT "oauth2_timeout"
#define OAUTH2_CONF_DEBUG "oauth2_debug"
#define OAUTH2_CONF_FALLBACK_CONFIG "oauth2_fallback_config"

/* Plugin API definition */
#ifdef WIN32
#define SASLPLUGINAPI __declspec(dllexport)
#else
#define SASLPLUGINAPI extern
#endif

/* Special return codes for configuration loading */
#define OAUTH2_CONFIG_NOT_FOUND SASL_CONTINUE  /* No configuration present - plugin inactive */

/* Default values */
#define OAUTH2_DEFAULT_USER_CLAIM "email"
#define OAUTH2_DEFAULT_SCOPE "openid email profile"
#define OAUTH2_DEFAULT_TIMEOUT 10
#define OAUTH2_DEFAULT_VERIFY_SIGNATURE 1
#define OAUTH2_DEFAULT_SSL_VERIFY 1
#define OAUTH2_DEFAULT_DEBUG 0
#define OAUTH2_DEFAULT_FALLBACK_CONFIG "/etc/sasl2/oauth2.conf"

/* Plugin configuration structure */
typedef struct oauth2_config {
    /* OIDC Discovery - support multiple URLs/issuers */
    char **discovery_urls;
    int discovery_urls_count;
    char **issuers;
    int issuers_count;
    char *client_id;
    char *client_secret;
    
    /* Token validation - support multiple audiences */
    char **audiences;
    int audiences_count;
    char *scope;
    char *user_claim;
    int verify_signature;
    
    /* Network settings */
    int ssl_verify;
    int timeout;
    int debug;
    
    /* Runtime state */
    oauth2_log_t *oauth2_log;
    int configured;  /* 1 if essential configuration is present, 0 if not */
    int client_id_allocated;  /* 1 if client_id was allocated (from fallback), 0 if from SASL */
} oauth2_config_t;

/* Function prototypes */

/* Utility functions */
char **oauth2_parse_string_list(const char *input, int *count);
void oauth2_free_string_list(char **list, int count);

/* oauth2_config.c */
oauth2_config_t *oauth2_config_init(const sasl_utils_t *utils);
void oauth2_config_free(oauth2_config_t *config);
int oauth2_config_load(oauth2_config_t *config, const sasl_utils_t *utils);

/* oauth2_server.c */
int oauth2_server_init(const sasl_utils_t *utils, oauth2_config_t *config);
int oauth2_server_step(void *conn_context, sasl_server_params_t *params,
                       const char *clientin, unsigned clientinlen,
                       const char **serverout, unsigned *serveroutlen,
                       sasl_out_params_t *oparams);
void oauth2_server_dispose(void *conn_context, const sasl_utils_t *utils);

/* oauth2_client.c */
int oauth2_client_init(const sasl_utils_t *utils, oauth2_config_t *config);
int oauth2_client_step(void *conn_context, sasl_client_params_t *params,
                       const char *serverin, unsigned serverinlen,
                       sasl_interact_t **prompt_need,
                       const char **clientout, unsigned *clientoutlen,
                       sasl_out_params_t *oparams);
void oauth2_client_dispose(void *conn_context, const sasl_utils_t *utils);

/* SASL mechanism functions - server */
int oauth2_server_mech_new(void *glob_context, sasl_server_params_t *params,
                           const char *challenge, unsigned challen, void **conn_context);
int oauth2_server_mech_step(void *conn_context, sasl_server_params_t *params,
                            const char *clientin, unsigned clientinlen,
                            const char **serverout, unsigned *serveroutlen,
                            sasl_out_params_t *oparams);
void oauth2_server_mech_dispose(void *conn_context, const sasl_utils_t *utils);

/* SASL mechanism functions - client */
int oauth2_client_mech_new(void *glob_context, sasl_client_params_t *params,
                           void **conn_context);
int oauth2_client_mech_step(void *conn_context, sasl_client_params_t *params,
                            const char *serverin, unsigned serverinlen,
                            sasl_interact_t **prompt_need,
                            const char **clientout, unsigned *clientoutlen,
                            sasl_out_params_t *oparams);
void oauth2_client_mech_dispose(void *conn_context, const sasl_utils_t *utils);

/* Utility functions */
#define OAUTH2_LOG_DEBUG(utils, format, ...) \
    (utils)->log((utils)->conn, SASL_LOG_DEBUG, "oauth2_plugin: " format, ##__VA_ARGS__)

#define OAUTH2_LOG_INFO(utils, format, ...) \
    (utils)->log((utils)->conn, SASL_LOG_NOTE, "oauth2_plugin: " format, ##__VA_ARGS__)

#define OAUTH2_LOG_WARN(utils, format, ...) \
    (utils)->log((utils)->conn, SASL_LOG_WARN, "oauth2_plugin: " format, ##__VA_ARGS__)

#define OAUTH2_LOG_ERR(utils, format, ...) \
    (utils)->log((utils)->conn, SASL_LOG_FAIL, "oauth2_plugin: " format, ##__VA_ARGS__)

/* Test utility function - FOR TESTING ONLY */
void oauth2_reset_global_config(void);

#endif /* OAUTH2_PLUGIN_H */