/*
 * OAuth2/OIDC SASL Plugin - Initialization
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "oauth2_plugin.h"
#include <stdlib.h>
#include <string.h>

#ifndef macintosh
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>
#endif

/* Global configuration instance */
static oauth2_config_t *global_config = NULL;

/* Test function to reset global state - FOR TESTING ONLY */
void oauth2_reset_global_config(void) {
    if (global_config) {
        oauth2_config_free(global_config);
        global_config = NULL;
    }
}

/* Global plugin lists */
static sasl_server_plug_t oauth2_server_plugins[] = {
    {
        OAUTH2_MECH_XOAUTH2,         /* mech_name */
        0,                           /* max_ssf */
        SASL_SEC_NOANONYMOUS
        | SASL_SEC_PASS_CREDENTIALS, /* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST 
        | SASL_FEAT_ALLOWS_PROXY,    /* features */
        NULL,                        /* glob_context */
        &oauth2_server_mech_new,     /* mech_new */
        &oauth2_server_mech_step,    /* mech_step */
        &oauth2_server_mech_dispose, /* mech_dispose */
        NULL,                        /* mech_free */
        NULL,                        /* setpass */
        NULL,                        /* user_query */
        NULL,                        /* idle */
        NULL,                        /* mech_avail */
        NULL                         /* spare */
    },
    {
        OAUTH2_MECH_OAUTHBEARER,     /* mech_name */
        0,                           /* max_ssf */
        SASL_SEC_NOANONYMOUS
        | SASL_SEC_PASS_CREDENTIALS, /* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST 
        | SASL_FEAT_ALLOWS_PROXY,    /* features */
        NULL,                        /* glob_context */
        &oauth2_server_mech_new,     /* mech_new */
        &oauth2_server_mech_step,    /* mech_step */
        &oauth2_server_mech_dispose, /* mech_dispose */
        NULL,                        /* mech_free */
        NULL,                        /* setpass */
        NULL,                        /* user_query */
        NULL,                        /* idle */
        NULL,                        /* mech_avail */
        NULL                         /* spare */
    }
};

static sasl_client_plug_t oauth2_client_plugins[] = {
    {
        OAUTH2_MECH_XOAUTH2,         /* mech_name */
        0,                           /* max_ssf */
        SASL_SEC_NOANONYMOUS
        | SASL_SEC_PASS_CREDENTIALS, /* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST 
        | SASL_FEAT_ALLOWS_PROXY,    /* features */
        NULL,                        /* required_prompts */
        NULL,                        /* glob_context */
        &oauth2_client_mech_new,     /* mech_new */
        &oauth2_client_mech_step,    /* mech_step */
        &oauth2_client_mech_dispose, /* mech_dispose */
        NULL,                        /* mech_free */
        NULL,                        /* idle */
        NULL,                        /* spare */
        NULL                         /* spare */
    },
    {
        OAUTH2_MECH_OAUTHBEARER,     /* mech_name */
        0,                           /* max_ssf */
        SASL_SEC_NOANONYMOUS
        | SASL_SEC_PASS_CREDENTIALS, /* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST 
        | SASL_FEAT_ALLOWS_PROXY,    /* features */
        NULL,                        /* required_prompts */
        NULL,                        /* glob_context */
        &oauth2_client_mech_new,     /* mech_new */
        &oauth2_client_mech_step,    /* mech_step */
        &oauth2_client_mech_dispose, /* mech_dispose */
        NULL,                        /* mech_free */
        NULL,                        /* idle */
        NULL,                        /* spare */
        NULL                         /* spare */
    }
};

/* Plugin initialization function for server - SASL will call this directly */
SASLPLUGINAPI int sasl_server_plug_init(const sasl_utils_t *utils,
                         int maxversion,
                         int *out_version,
                         sasl_server_plug_t **pluglist,
                         int *plugcount) {
    
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
        utils->log(utils->conn, SASL_LOG_ERR, "oauth2_plugin: Version mismatch - got %d, need %d", 
                  maxversion, SASL_SERVER_PLUG_VERSION);
        utils->seterror(utils->conn, 0, "OAuth2: version mismatch");
        return SASL_BADVERS;
    }
    
    /* Initialize global configuration if not already done */
    if (!global_config) {
        global_config = oauth2_config_init(utils);
        if (!global_config) {
            utils->log(utils->conn, SASL_LOG_ERR, "oauth2_plugin: Failed to initialize configuration");
            utils->seterror(utils->conn, 0, "OAuth2: Failed to initialize configuration");
            return SASL_FAIL;
        }
        
        /* Load configuration - allow graceful handling of missing config */
        int config_result = oauth2_config_load(global_config, utils);
        if (config_result == OAUTH2_CONFIG_NOT_FOUND) {
            /* No OAuth2 configuration found - plugin will remain inactive but registered */
            utils->log(utils->conn, SASL_LOG_DEBUG, "oauth2_plugin: No configuration found - plugin inactive");
        } else if (config_result != SASL_OK) {
            /* Configuration was attempted but invalid - this is an error */
            utils->log(utils->conn, SASL_LOG_ERR, "oauth2_plugin: Config load failed with %d - invalid configuration", config_result);
            utils->seterror(utils->conn, 0, "OAuth2: Invalid configuration");
            oauth2_config_free(global_config);
            global_config = NULL;
            return SASL_FAIL;
        }
        
        /* Initialize server mechanisms only if configuration is present */
        if (global_config->configured) {
            int server_init_result = oauth2_server_init(utils, global_config);
            if (server_init_result != SASL_OK) {
                utils->log(utils->conn, SASL_LOG_WARN, "oauth2_plugin: Server init failed with %d", server_init_result);
            }
        }
    }
    
    /* Set global context in mechanism descriptors */
    oauth2_server_plugins[0].glob_context = global_config;
    oauth2_server_plugins[1].glob_context = global_config;
    
    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = oauth2_server_plugins;
    *plugcount = 2;
    
    utils->log(utils->conn, SASL_LOG_NOTE, "oauth2_plugin: Registered mechanisms: %s, %s", 
              oauth2_server_plugins[0].mech_name, oauth2_server_plugins[1].mech_name);
    
    return SASL_OK;
}

/* Plugin initialization function for client - SASL will call this directly */
SASLPLUGINAPI int sasl_client_plug_init(const sasl_utils_t *utils,
                         int maxversion,
                         int *out_version,
                         sasl_client_plug_t **pluglist,
                         int *plugcount) {
    
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
        utils->seterror(utils->conn, 0, "OAuth2: version mismatch");
        return SASL_BADVERS;
    }
    
    /* Use global configuration if already initialized */
    if (!global_config) {
        global_config = oauth2_config_init(utils);
        if (!global_config) {
            utils->seterror(utils->conn, 0, "OAuth2: Failed to initialize configuration");
            return SASL_FAIL;
        }
        
        int config_result = oauth2_config_load(global_config, utils);
        if (config_result == OAUTH2_CONFIG_NOT_FOUND) {
            /* No OAuth2 configuration found - plugin will remain inactive but registered */
            /* Don't set error for client - allow graceful operation */
        } else if (config_result != SASL_OK) {
            /* Configuration was attempted but invalid - this is an error */
            utils->seterror(utils->conn, 0, "OAuth2: Invalid configuration");
            oauth2_config_free(global_config);
            global_config = NULL;
            return SASL_FAIL;
        }
    }
    
    /* Initialize client mechanisms only if configuration is present */
    if (global_config->configured && oauth2_client_init(utils, global_config) != SASL_OK) {
        utils->seterror(utils->conn, 0, "OAuth2: Failed to initialize client");
        if (!oauth2_server_plugins[0].glob_context) { /* Only free if server didn't set it */
            oauth2_config_free(global_config);
            global_config = NULL;
        }
        return SASL_FAIL;
    }
    
    /* Set global context in mechanism descriptors */
    oauth2_client_plugins[0].glob_context = global_config;
    oauth2_client_plugins[1].glob_context = global_config;
    
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = oauth2_client_plugins;
    *plugcount = 2;
    
    return SASL_OK;
}