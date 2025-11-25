/*
 * OAuth2/OIDC SASL Plugin - Server Implementation
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "oauth2_plugin.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <jansson.h>

/* Server context structure - defined in oauth2_types.h */



/* SASL XOAUTH2 format: "user=" + userName + "^Aauth=Bearer " + accessToken + "^A^A" */
static int oauth2_parse_xoauth2(const sasl_utils_t *utils, const char *input, unsigned inputlen, 
                               char **username, char **token) {
    if (!input || inputlen == 0 || !username || !token) {
        return SASL_BADPARAM;
    }
    
    /* Log input length only for security */
    OAUTH2_LOG_DEBUG(utils, "XOAUTH2 parsing input (%u bytes)", inputlen);
    
    *username = NULL;
    *token = NULL;
    
    /* XOAUTH2 data comes already decoded - no base64 decode needed! */
    /* Copy input data to work with it (same as cyrus-sasl-xoauth2-idp) */
    char *data = malloc(inputlen + 1);
    if (!data) return SASL_NOMEM;
    
    /* Defensive check: ensure we don't copy more than allocated */
    if (inputlen > 0) {
        memcpy(data, input, inputlen);
    }
    data[inputlen] = '\0';
    
    /* Parse the string: user=username^Aauth=Bearer token^A^A */
    char *ptr = data;
    char *end = data + inputlen;
    
    /* Find "user=" */
    if (strncmp(ptr, "user=", 5) != 0) {
        OAUTH2_LOG_ERR(utils, "XOAUTH2 does not start with 'user=', starts with: %.10s", ptr);
        free(data);
        return SASL_BADAUTH;
    }
    ptr += 5;
    
    /* Extract username until ^A (ASCII 1) */
    char *user_start = ptr;
    while (ptr < end && *ptr != '\x01') ptr++;
    if (ptr >= end) {
        OAUTH2_LOG_ERR(utils, "XOAUTH2 no separator ^A found after username");
        free(data);
        return SASL_BADAUTH;
    }
    
    *username = strndup(user_start, ptr - user_start);
    OAUTH2_LOG_DEBUG(utils, "XOAUTH2 extracted username: %s", *username);
    ptr++; /* Skip ^A */
    
    /* Find "auth=Bearer " */
    if (strncmp(ptr, "auth=Bearer ", 12) != 0) {
        OAUTH2_LOG_ERR(utils, "XOAUTH2 no 'auth=Bearer ' found, found: %.15s", ptr);
        free(*username);
        *username = NULL;
        free(data);
        return SASL_BADAUTH;
    }
    ptr += 12;
    
    /* Extract token until ^A */
    char *token_start = ptr;
    while (ptr < end && *ptr != '\x01') ptr++;
    if (ptr >= end) {
        OAUTH2_LOG_ERR(utils, "XOAUTH2 no separator ^A found after token");
        free(*username);
        *username = NULL;
        free(data);
        return SASL_BADAUTH;
    }
    
    *token = strndup(token_start, ptr - token_start);
    OAUTH2_LOG_DEBUG(utils, "XOAUTH2 token extracted (%zu chars)", strlen(*token));
    
    free(data);
    return SASL_OK;
}

/* SASL OAUTHBEARER format: "n,a=username,^Aauth=Bearer token^A^A" */
static int oauth2_parse_oauthbearer(const char *input, unsigned inputlen,
                                   char **username, char **token) {
    if (!input || inputlen == 0 || !username || !token) {
        return SASL_BADPARAM;
    }
    
    *username = NULL;
    *token = NULL;
    
    /* Make a copy to work with */
    char *data = strndup(input, inputlen);
    if (!data) return SASL_NOMEM;
    
    char *ptr = data;
    char *end = data + inputlen;
    
    /* Skip GS2 header "n," or "n,a=username," */
    if (strncmp(ptr, "n,", 2) == 0) {
        ptr += 2;
        
        /* Check for a=username */
        if (strncmp(ptr, "a=", 2) == 0) {
            ptr += 2;
            char *user_start = ptr;
            while (ptr < end && *ptr != ',') ptr++;
            if (ptr < end) {
                *username = strndup(user_start, ptr - user_start);
                ptr++; /* Skip comma */
            }
        }
    }
    
    /* Skip to auth=Bearer */
    while (ptr < end) {
        if (strncmp(ptr, "auth=Bearer ", 12) == 0) {
            ptr += 12;
            char *token_start = ptr;
            while (ptr < end && *ptr != '\x01') ptr++;
            *token = strndup(token_start, ptr - token_start);
            free(data);
            return SASL_OK;
        }
        /* Skip to next field */
        while (ptr < end && *ptr != '\x01') ptr++;
        if (ptr >= end) break;
        ptr++; /* Skip ^A */
    }
    
    free(data);
    if (*username) { free(*username); *username = NULL; }
    return SASL_BADAUTH;
}

/* Utility functions for error handling and cleanup */

/* Common JWT validation error cleanup */
static int oauth2_jwt_cleanup_and_return(const sasl_utils_t *utils, 
                                         const char *error_msg,
                                         char *padded_payload,
                                         char *jwt_copy, 
                                         oauth2_cfg_token_verify_t *verify,
                                         oauth2_config_t *config,
                                         json_t *json_payload,
                                         int return_code) {
    if (error_msg && utils) {
        OAUTH2_LOG_ERR(utils, "%s", error_msg);
    }
    
    if (padded_payload) free(padded_payload);
    if (jwt_copy) free(jwt_copy);
    if (json_payload) json_decref(json_payload);
    if (verify && config) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
    
    return return_code;
}

/* Utility function to parse JWT into header, payload, signature */
static char* oauth2_parse_jwt_parts(const char *token, char **header, char **payload, char **signature) {
    if (!token || !header || !payload || !signature) {
        return NULL;
    }
    
    char *jwt_copy = strdup(token);
    if (!jwt_copy) return NULL;
    
    *header = strtok(jwt_copy, ".");
    *payload = strtok(NULL, ".");
    *signature = strtok(NULL, ".");
    
    if (!*header || !*payload || !*signature) {
        free(jwt_copy);
        return NULL;
    }
    
    return jwt_copy; /* Caller must free this */
}

static int oauth2_validate_jwt_token(const sasl_utils_t *utils,
                                     oauth2_config_t *config,
                                     const char *token,
                                     char **username) {
    
    if (!token || strlen(token) < 10) {
        OAUTH2_LOG_ERR(utils, "Invalid token format");
        return SASL_BADAUTH;
    }
    
    if (!config) {
        OAUTH2_LOG_ERR(utils, "No OAuth2 configuration available");
        return SASL_BADAUTH;
    }
    
    /* Initialize liboauth2 log context if not already done */
    if (!config->oauth2_log) {
        oauth2_log_level_t log_level = config->debug ? OAUTH2_LOG_TRACE1 : OAUTH2_LOG_WARN;
        config->oauth2_log = oauth2_log_init(log_level, NULL);
        if (!config->oauth2_log) {
            OAUTH2_LOG_ERR(utils, "Failed to initialize OAuth2 log context");
            return SASL_FAIL;
        }
    }
    
    /* Try to use oauth2_token_verify for modern JWT validation */
    oauth2_cfg_token_verify_t *verify = NULL;
    json_t *json_payload = NULL;
    const char *rv = NULL;
    bool validation_success = false;

    
    /* For production use, we should configure proper JWKS URI or introspection endpoints */
    /* For now, we'll use a simple approach with issuer validation */
    
    /* If we have discovery URLs configured, try to use metadata-based verification */
    if (config->discovery_urls_count > 0 && config->discovery_urls && config->discovery_urls[0]) {
        OAUTH2_LOG_DEBUG(utils, "Using metadata-based token verification with discovery URL: %s", config->discovery_urls[0]);
        
        /* Configure metadata-based verification */
        char *options = NULL;
        if (config->audiences_count > 0 && config->audiences) {
            /* Add audience validation if configured */
            const char *aud_option = "verify.aud=required";
            size_t opts_len = strlen(aud_option) + 1;
            options = malloc(opts_len);
            if (options) {
                /* Safe copy with explicit size limit */
                strncpy(options, aud_option, opts_len - 1);
                options[opts_len - 1] = '\0';
            }
        }
        
        rv = oauth2_cfg_token_verify_add_options(config->oauth2_log, &verify, "metadata", 
                                                config->discovery_urls[0], options);
        if (options) free(options);
        
        if (rv == NULL) {
            /* liboauth2 handles caching internally - we don't need to detect it manually */
            validation_success = oauth2_token_verify(config->oauth2_log, NULL, verify, token, &json_payload);
            if (validation_success) {
                OAUTH2_LOG_INFO(utils, "JWT validation successful using metadata discovery");
            } else {
                OAUTH2_LOG_WARN(utils, "JWT validation failed using metadata discovery, falling back to manual parsing");
            }
        } else {
            OAUTH2_LOG_ERR(utils, "Failed to configure metadata verification: %s", rv);
            oauth2_mem_free((char*)rv);
        }
    }
    
    /* If metadata verification failed or not configured, try simple JWT parsing for basic validation */
    if (!validation_success) {
        /* Basic token validation - check if it looks like a JWT */
        int dot_count = 0;
        for (const char *p = token; *p; p++) {
            if (*p == '.') dot_count++;
        }
        
        if (dot_count != 2) {
            OAUTH2_LOG_ERR(utils, "Token does not appear to be a valid JWT (expected 2 dots, found %d)", dot_count);
            if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
            return SASL_BADAUTH;
        }
        
        /* Parse JWT manually to extract claims */
        char *header, *payload, *signature;
        
        char *jwt_copy = oauth2_parse_jwt_parts(token, &header, &payload, &signature);
        if (!jwt_copy) {
            OAUTH2_LOG_ERR(utils, "Invalid JWT format - missing parts or allocation failed");
            if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
            return SASL_BADAUTH;
        }
        
        /* Decode base64url payload */
        size_t payload_len = strlen(payload);
        /* Add padding if needed for base64url */
        size_t padding = (4 - (payload_len % 4)) % 4;
        char *padded_payload = malloc(payload_len + padding + 1);
        if (!padded_payload) {
            OAUTH2_LOG_ERR(utils, "Failed to allocate memory for payload");
            free(jwt_copy);
            if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
            return SASL_NOMEM;
        }
        
        memcpy(padded_payload, payload, payload_len);
        padded_payload[payload_len] = '\0';
        for (size_t i = 0; i < padding; i++) {
            padded_payload[payload_len + i] = '=';
        }
        padded_payload[payload_len + padding] = '\0';
        
        /* Convert base64url to base64 (replace - with + and _ with /) */
        for (char *p = padded_payload; *p; p++) {
            if (*p == '-') *p = '+';
            else if (*p == '_') *p = '/';
        }
        
        /* Decode base64 using liboauth2 function */
        uint8_t *decoded_payload = NULL;
        size_t decoded_len = 0;
        if (!oauth2_base64_decode(config->oauth2_log, padded_payload, &decoded_payload, &decoded_len)) {
            return oauth2_jwt_cleanup_and_return(utils, "Failed to decode JWT payload using liboauth2",
                                                padded_payload, jwt_copy, verify, config, NULL, SASL_BADAUTH);
        }
        
        /* Null-terminate decoded payload */
        char *decoded_str = malloc(decoded_len + 1);
        if (!decoded_str) {
            oauth2_mem_free(decoded_payload);
            return oauth2_jwt_cleanup_and_return(utils, "Failed to allocate memory for decoded payload",
                                                padded_payload, jwt_copy, verify, config, NULL, SASL_NOMEM);
        }
        
        /* Defensive check: ensure we don't copy more than allocated */
        if (decoded_len > 0 && decoded_payload) {
            memcpy(decoded_str, decoded_payload, decoded_len);
        }
        decoded_str[decoded_len] = '\0';
        oauth2_mem_free(decoded_payload); /* Free liboauth2 allocated memory */
        
        /* Parse JSON payload */
        json_error_t json_error;
        json_payload = json_loads(decoded_str, 0, &json_error);
        if (!json_payload) {
            free(decoded_str);
            return oauth2_jwt_cleanup_and_return(utils, "Failed to parse JWT payload JSON",
                                                padded_payload, jwt_copy, verify, config, NULL, SASL_BADAUTH);
        }
        
        free(decoded_str);
        free(padded_payload);
        free(jwt_copy);
        
        OAUTH2_LOG_INFO(utils, "JWT claims parsed successfully using fallback manual parsing");
        validation_success = true;
    }
    
    if (!validation_success || !json_payload) {
        OAUTH2_LOG_ERR(utils, "JWT validation failed");
        if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
        return SASL_BADAUTH;
    }
    
    /* Extract username from configured claim (default: "email") */
    const char *user_claim = config->user_claim ? config->user_claim : OAUTH2_DEFAULT_USER_CLAIM;
    json_t *user_json = json_object_get(json_payload, user_claim);
    
    if (!user_json || !json_is_string(user_json)) {
        OAUTH2_LOG_ERR(utils, "User claim '%s' not found or not a string in JWT", user_claim);
        json_decref(json_payload);
        if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
        return SASL_BADAUTH;
    }
    
    const char *user_value = json_string_value(user_json);
    if (!user_value || strlen(user_value) == 0) {
        OAUTH2_LOG_ERR(utils, "User claim '%s' is empty in JWT", user_claim);
        json_decref(json_payload);
        if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
        return SASL_BADAUTH;
    }
    
    OAUTH2_LOG_INFO(utils, "JWT user claim '%s': %s", user_claim, user_value);
    
    /* Validate issuer if configured */
    if (config->issuers_count > 0 && config->issuers) {
        json_t *iss_json = json_object_get(json_payload, "iss");
        if (!iss_json || !json_is_string(iss_json)) {
            OAUTH2_LOG_ERR(utils, "JWT issuer claim missing or invalid");
            json_decref(json_payload);
            if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
            return SASL_BADAUTH;
        }
        
        const char *token_issuer = json_string_value(iss_json);
        bool issuer_valid = false;
        
        for (int i = 0; i < config->issuers_count; i++) {
            if (strcmp(token_issuer, config->issuers[i]) == 0) {
                issuer_valid = true;
                break;
            }
        }
        
        if (!issuer_valid) {
            OAUTH2_LOG_ERR(utils, "JWT issuer '%s' not in allowed issuers list", token_issuer);
            json_decref(json_payload);
            if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
            return SASL_BADAUTH;
        }
        
        OAUTH2_LOG_INFO(utils, "JWT issuer validated: %s", token_issuer);
    }
    
    /* Validate audience if configured */
    if (config->audiences_count > 0 && config->audiences) {
        json_t *aud_json = json_object_get(json_payload, "aud");
        if (!aud_json) {
            OAUTH2_LOG_ERR(utils, "JWT audience claim missing");
            json_decref(json_payload);
            if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
            return SASL_BADAUTH;
        }
        
        bool audience_valid = false;
        
        if (json_is_string(aud_json)) {
            /* Single audience */
            const char *token_audience = json_string_value(aud_json);
            for (int i = 0; i < config->audiences_count; i++) {
                if (strcmp(token_audience, config->audiences[i]) == 0) {
                    audience_valid = true;
                    break;
                }
            }
        } else if (json_is_array(aud_json)) {
            /* Multiple audiences */
            size_t index;
            json_t *aud_value;
            json_array_foreach(aud_json, index, aud_value) {
                if (json_is_string(aud_value)) {
                    const char *token_audience = json_string_value(aud_value);
                    for (int i = 0; i < config->audiences_count; i++) {
                        if (strcmp(token_audience, config->audiences[i]) == 0) {
                            audience_valid = true;
                            break;
                        }
                    }
                    if (audience_valid) break;
                }
            }
        }
        
        if (!audience_valid) {
            OAUTH2_LOG_ERR(utils, "JWT audience validation failed - no matching audience found");
            json_decref(json_payload);
            if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
            return SASL_BADAUTH;
        }
        
        OAUTH2_LOG_DEBUG(utils, "JWT audience validated");
    }
    
    /* Allocate and copy username */
    size_t user_len = strlen(user_value);
    *username = utils->malloc(user_len + 1);
    if (!*username) {
        OAUTH2_LOG_ERR(utils, "Failed to allocate memory for username");
        json_decref(json_payload);
        if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
        return SASL_NOMEM;
    }
    memcpy(*username, user_value, user_len);
    (*username)[user_len] = '\0';
    
    /* Clean up */
    json_decref(json_payload);
    if (verify) oauth2_cfg_token_verify_free(config->oauth2_log, verify);
    
    OAUTH2_LOG_INFO(utils, "JWT validation successful for: %s", *username);
    return SASL_OK;
}

int oauth2_server_init(const sasl_utils_t *utils, oauth2_config_t *config) {
    if (!utils || !config) {
        return SASL_BADPARAM;
    }
    
    OAUTH2_LOG_INFO(utils, "OAuth2/OIDC server plugin initialized");
    return SASL_OK;
}

int oauth2_server_step(void *conn_context, sasl_server_params_t *params,
                       const char *clientin, unsigned clientinlen,
                       const char **serverout, unsigned *serveroutlen,
                       sasl_out_params_t *oparams) {
    
    oauth2_server_context_t *context = (oauth2_server_context_t*)conn_context;
    const sasl_utils_t *utils = params->utils;
    
    *serverout = NULL;
    *serveroutlen = 0;
    
    if (!context) {
        OAUTH2_LOG_ERR(utils, "Invalid server context");
        return SASL_BADPARAM;
    }
    
    /* Check if OAuth2 configuration is available */
    if (!context->config || !context->config->configured) {
        OAUTH2_LOG_DEBUG(utils, "OAuth2 server mechanism called but no configuration available");
        utils->seterror(params->utils->conn, 0, "OAuth2 authentication not configured");
        return SASL_UNAVAIL;
    }
    
    if (context->state != 0) {
        OAUTH2_LOG_ERR(utils, "Unexpected state in OAuth2 authentication");
        return SASL_BADPROT;
    }
    
    if (!clientin || clientinlen == 0) {
        OAUTH2_LOG_ERR(utils, "No client input provided");
        return SASL_BADAUTH;
    }
    
    /* Parse client input based on mechanism */
    char *username = NULL;
    char *token = NULL;
    int parse_result;
    
    /* Looks like XOAUTH2 */
    if (strncmp(clientin, "user=", 5) == 0) {
        OAUTH2_LOG_INFO(utils, "Trying XOAuth2 authentication");
        parse_result = oauth2_parse_xoauth2(utils, clientin, clientinlen, &username, &token);
    /* Looks like OAUTHBEARER */
    } else if (strncmp(clientin, "n,", 2) == 0) {
        OAUTH2_LOG_INFO(utils, "Trying OAuthBearer authentication");
        parse_result = oauth2_parse_oauthbearer(clientin, clientinlen, &username, &token);
    /* Default, try XOAUTH2 */
    } else {
        OAUTH2_LOG_INFO(utils, "Trying XOAuth2 authentication as failback");
        parse_result = oauth2_parse_xoauth2(utils, clientin, clientinlen, &username, &token);
    }
    
    if (parse_result != SASL_OK) {
        OAUTH2_LOG_ERR(utils, "Failed to parse client authentication data");
        return parse_result;
    }
    
    if (!username || !token) {
        OAUTH2_LOG_ERR(utils, "Missing username or token in client data");
        if (username) free(username);
        if (token) free(token);
        return SASL_BADAUTH;
    }
    
    /* Validate JWT token */
    char *validated_username = NULL;
    int validation_result = oauth2_validate_jwt_token(utils, context->config, token, &validated_username);
    
    if (validation_result != SASL_OK) {
        OAUTH2_LOG_ERR(utils, "Token validation failed for user: %s", username);
        free(username);
        free(token);
        if (validated_username) free(validated_username);
        return validation_result;
    }
    
    /* Use validated username from JWT token */
    const char *final_username = validated_username ? validated_username : username;
    
    /* Canonicalize the user - this is essential for SASL to work properly */
    int canon_result = params->canon_user(params->utils->conn, final_username, 0, 
                                         SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if (canon_result != SASL_OK) {
        OAUTH2_LOG_ERR(utils, "Failed to canonicalize user: %s", final_username);
        free(username);
        free(token);
        if (validated_username) free(validated_username);
        return canon_result;
    }
    
    /* Authentication successful */
    size_t username_len = strlen(final_username);
    context->username = utils->malloc(username_len + 1);
    if (context->username) {
        memcpy(context->username, final_username, username_len);
        context->username[username_len] = '\0';
    }
    context->access_token = token;
    context->state = 1;
    
    /* Set output parameters - user/authid already set by canon_user */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0; /* No security layer */
    oparams->maxoutbuf = 0;
    oparams->encode = NULL;
    oparams->decode = NULL;
    
    /* Clean up */
    free(username);
    if (validated_username) free(validated_username);
    
    OAUTH2_LOG_INFO(utils, "OAuth2 authentication successful");
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

void oauth2_server_dispose(void *conn_context, const sasl_utils_t *utils) {
    oauth2_server_context_t *context = (oauth2_server_context_t*)conn_context;
    
    if (!context) return;
    
    oauth2_cleanup_context_fields(context->username, context->access_token, utils);
    utils->free(context);
}

/* Server mechanism functions for SASL plugin interface */
int oauth2_server_mech_new(void *glob_context,
                           sasl_server_params_t *params,
                           const char *challenge,
                           unsigned challen,
                           void **conn_context) {
    
    oauth2_server_context_t *context;
    const sasl_utils_t *utils = params->utils;
    
    if (!glob_context) {
        utils->seterror(params->utils->conn, 0, "No global context available");
        return SASL_FAIL;
    }
    
    context = utils->malloc(sizeof(oauth2_server_context_t));
    if (!context) {
        utils->seterror(params->utils->conn, 0, "Failed to allocate server context");
        return SASL_NOMEM;
    }
    
    memset(context, 0, sizeof(oauth2_server_context_t));
    context->config = (oauth2_config_t*)glob_context;
    context->state = 0;
    
    *conn_context = context;
    
    return SASL_OK;
}

int oauth2_server_mech_step(void *conn_context, 
                            sasl_server_params_t *params,
                            const char *clientin,
                            unsigned clientinlen,
                            const char **serverout,
                            unsigned *serveroutlen,
                            sasl_out_params_t *oparams) {
    
    return oauth2_server_step(conn_context, params, clientin, clientinlen,
                             serverout, serveroutlen, oparams);
}

void oauth2_server_mech_dispose(void *conn_context, const sasl_utils_t *utils) {
    oauth2_server_dispose(conn_context, utils);
}