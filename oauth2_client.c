/*
 * OAuth2/OIDC SASL Plugin - Client Implementation
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "oauth2_plugin.h"
#include <stdlib.h>
#include <string.h>

/* Client context structure - defined in oauth2_types.h */

/* Generate XOAUTH2 authentication string */
static int oauth2_generate_xoauth2(const char *username, const char *token,
                                  char **output, unsigned *outputlen) {
    if (!username || !token || !output || !outputlen) {
        return SASL_BADPARAM;
    }
    
    /* Format: user=username^Aauth=Bearer token^A^A */
    size_t auth_len = strlen("user=") + strlen(username) + 1 + /* ^A */
                      strlen("auth=Bearer ") + strlen(token) + 2; /* ^A^A */
    
    char *auth_string = malloc(auth_len);
    if (!auth_string) {
        return SASL_NOMEM;
    }
    
    int snprintf_result = snprintf(auth_string, auth_len, "user=%s\x01auth=Bearer %s\x01\x01", username, token);
    if (snprintf_result < 0 || (size_t)snprintf_result >= auth_len) {
        free(auth_string);
        return SASL_FAIL;
    }
    
    /* Base64 encode the authentication string */
    char *encoded = NULL;
    size_t encoded_len = 0;
    
    /* Use liboauth2 v2.10+ API - returns size_t, not bool */
    encoded_len = oauth2_base64_encode(NULL, (const uint8_t*)auth_string, auth_len - 1, &encoded);
    if (encoded_len == 0 || !encoded) {
        free(auth_string);
        return SASL_FAIL;
    }
    
    free(auth_string);
    
    *output = encoded;
    *outputlen = encoded_len;
    
    return SASL_OK;
}

/* Generate OAUTHBEARER authentication string */
/*@unused@*/ static int oauth2_generate_oauthbearer(const char *username, const char *token,
                                      char **output, unsigned *outputlen) {
    if (!username || !token || !output || !outputlen) {
        return SASL_BADPARAM;
    }
    
    /* Format: n,a=username,^Aauth=Bearer token^A^A */
    size_t auth_len = strlen("n,a=") + strlen(username) + strlen(",\x01auth=Bearer ") + 
                      strlen(token) + strlen("\x01\x01") + 1;
    
    char *auth_string = malloc(auth_len);
    if (!auth_string) {
        return SASL_NOMEM;
    }
    
    int snprintf_result = snprintf(auth_string, auth_len, "n,a=%s,\x01auth=Bearer %s\x01\x01", username, token);
    if (snprintf_result < 0 || (size_t)snprintf_result >= auth_len) {
        free(auth_string);
        return SASL_FAIL;
    }
    
    *output = auth_string;
    *outputlen = strlen(auth_string);
    
    return SASL_OK;
}

int oauth2_client_init(const sasl_utils_t *utils, oauth2_config_t *config) {
    if (!utils || !config) {
        return SASL_BADPARAM;
    }
    
    /* Initialize liboauth2 log context if not already done */
    if (!config->oauth2_log) {
        oauth2_log_level_t log_level = config->debug ? OAUTH2_LOG_TRACE1 : OAUTH2_LOG_WARN;
        config->oauth2_log = oauth2_log_init(log_level, NULL);
        if (!config->oauth2_log) {
            OAUTH2_LOG_ERR(utils, "Failed to initialize OAuth2 log context for client");
            return SASL_FAIL;
        }
    }
    
    OAUTH2_LOG_INFO(utils, "OAuth2/OIDC client plugin initialized");
    return SASL_OK;
}

int oauth2_client_step(void *conn_context, sasl_client_params_t *params,
                       /*@unused@*/ const char *serverin, /*@unused@*/ unsigned serverinlen,
                       sasl_interact_t **prompt_need,
                       const char **clientout, unsigned *clientoutlen,
                       sasl_out_params_t *oparams) {
    
    oauth2_client_context_t *context = (oauth2_client_context_t*)conn_context;
    const sasl_utils_t *utils = params->utils;
    
    *clientout = NULL;
    *clientoutlen = 0;
    *prompt_need = NULL;
    
    if (!context) {
        OAUTH2_LOG_ERR(utils, "Invalid client context");
        return SASL_BADPARAM;
    }
    
    /* Check if OAuth2 configuration is available */
    if (!context->config || !context->config->configured) {
        OAUTH2_LOG_DEBUG(utils, "OAuth2 client mechanism called but no configuration available");
        utils->seterror(params->utils->conn, 0, "OAuth2 authentication not configured");
        return SASL_UNAVAIL;
    }
    
    if (context->state != 0) {
        OAUTH2_LOG_ERR(utils, "Unexpected state in OAuth2 client authentication");
        return SASL_BADPROT;
    }
    
    /* We expect to have username and access token from previous interactions */
    if (!context->username || !context->access_token) {
        /* Request username and access token via prompts */
        sasl_interact_t *prompts = utils->malloc(3 * sizeof(sasl_interact_t));
        if (!prompts) {
            return SASL_NOMEM;
        }
        
        memset(prompts, 0, 3 * sizeof(sasl_interact_t));
        
        /* Username prompt */
        prompts[0].id = SASL_CB_USER;
        prompts[0].challenge = "Username";
        prompts[0].prompt = "Please enter username: ";
        prompts[0].defresult = NULL;
        
        /* Access token prompt */
        prompts[1].id = SASL_CB_PASS;
        prompts[1].challenge = "Access Token";
        prompts[1].prompt = "Please enter OAuth2 access token: ";
        prompts[1].defresult = NULL;
        
        /* End of prompts */
        prompts[2].id = SASL_CB_LIST_END;
        
        *prompt_need = prompts;
        return SASL_INTERACT;
    }
    
    /* Generate authentication string based on mechanism */
    char *auth_output = NULL;
    unsigned auth_len = 0;
    int result;
    
    /* Use XOAUTH2 mechanism (simplified approach) */
    result = oauth2_generate_xoauth2(context->username, context->access_token,
                                    &auth_output, &auth_len);
    
    if (result != SASL_OK) {
        OAUTH2_LOG_ERR(utils, "Failed to generate authentication string");
        return result;
    }
    
    *clientout = auth_output;
    *clientoutlen = auth_len;
    
    context->state = 1;
    
    /* Set output parameters */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0; /* No security layer */
    oparams->maxoutbuf = 0;
    oparams->encode = NULL;
    oparams->decode = NULL;
    /* realm member doesn't exist in modern SASL */
    /* Free any existing user/authid before setting new ones */
    if (oparams->user) {
        utils->free((void*)oparams->user);
        oparams->user = NULL;
    }
    if (oparams->authid) {
        utils->free((void*)oparams->authid);
        oparams->authid = NULL;
    }
    
    /* Allocate and set user and authid */
    size_t username_len = strlen(context->username);
    char *user_copy = utils->malloc(username_len + 1);
    char *authid_copy = utils->malloc(username_len + 1);
    
    if (user_copy) {
        strncpy(user_copy, context->username, username_len);
        user_copy[username_len] = '\0';
        oparams->user = user_copy;
    }
    if (authid_copy) {
        strncpy(authid_copy, context->username, username_len);
        authid_copy[username_len] = '\0';
        oparams->authid = authid_copy;
    }
    
    OAUTH2_LOG_INFO(utils, "OAuth2 client authentication data generated for user: %s", 
                   context->username);
    
    return SASL_OK;
}

/* Common cleanup utility for OAuth2 contexts */
static void oauth2_cleanup_context_fields(char *username, char *access_token, const sasl_utils_t *utils) {
    if (username) {
        utils->free(username);
    }
    
    if (access_token) {
        /* Clear token from memory for security */
        memset(access_token, 0, strlen(access_token));
        utils->free(access_token);
    }
}

void oauth2_client_dispose(void *conn_context, const sasl_utils_t *utils) {
    oauth2_client_context_t *context = (oauth2_client_context_t*)conn_context;
    
    if (!context) return;
    
    oauth2_cleanup_context_fields(context->username, context->access_token, utils);
    utils->free(context);
}

/* Client mechanism functions for SASL plugin interface */
int oauth2_client_mech_new(void *glob_context,
                           sasl_client_params_t *params,
                           void **conn_context) {
    
    oauth2_client_context_t *context;
    const sasl_utils_t *utils = params->utils;
    
    if (!glob_context) {
        utils->seterror(params->utils->conn, 0, "No global context available");
        return SASL_FAIL;
    }
    
    context = utils->malloc(sizeof(oauth2_client_context_t));
    if (!context) {
        utils->seterror(params->utils->conn, 0, "Failed to allocate client context");
        return SASL_NOMEM;
    }
    
    memset(context, 0, sizeof(oauth2_client_context_t));
    context->config = (oauth2_config_t*)glob_context;
    context->state = 0;
    
    *conn_context = context;
    
    return SASL_OK;
}

int oauth2_client_mech_step(void *conn_context,
                            sasl_client_params_t *params,
                            const char *serverin,
                            unsigned serverinlen,
                            sasl_interact_t **prompt_need,
                            const char **clientout,
                            unsigned *clientoutlen,
                            sasl_out_params_t *oparams) {
    
    return oauth2_client_step(conn_context, params, serverin, serverinlen,
                             prompt_need, clientout, clientoutlen, oparams);
}

void oauth2_client_mech_dispose(void *conn_context, const sasl_utils_t *utils) {
    oauth2_client_dispose(conn_context, utils);
}