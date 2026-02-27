AC_PREREQ([2.69])
AC_INIT([cyrus-sasl-oauth2-oidc], [1.0.2], [stefb@wizzz.net])
AC_CONFIG_SRCDIR([oauth2_plugin.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

# Checks for programs
AC_PROG_CC
AM_PROG_AR
LT_INIT

# Checks for libraries
# Try different function names from liboauth2
AC_CHECK_LIB([oauth2], [oauth2_init], [HAVE_OAUTH2=yes], [
    AC_CHECK_LIB([oauth2], [oauth2_init], [HAVE_OAUTH2=yes], [
        AC_CHECK_LIB([oauth2], [oauth2_version], [HAVE_OAUTH2=yes], [
            AC_MSG_ERROR([liboauth2 is required but not found. Make sure it's installed in /usr/local and LD_LIBRARY_PATH is set.])
        ])
    ])
])

AC_CHECK_LIB([cjose], [cjose_jwk_create_RSA_spec], [], [
    AC_CHECK_LIB([cjose], [cjose_header_set], [], [
        AC_CHECK_LIB([cjose], [cjose_jws_verify], [], [
            AC_MSG_ERROR([libcjose is required but not found. Please install libcjose-dev.])
        ])
    ])
])

AC_CHECK_LIB([jansson], [json_object], [], [
    AC_MSG_ERROR([libjansson is required but not found. Please install libjansson-dev.])
])

# jansson is provided by liboauth2 dependency

AC_CHECK_LIB([curl], [curl_easy_init], [], [
    AC_MSG_ERROR([libcurl is required but not found. Please install libcurl4-openssl-dev.])
])

AC_CHECK_LIB([ssl], [SSL_CTX_new], [], [
    AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [], [
        AC_MSG_ERROR([OpenSSL is required but not found. Please install libssl-dev.])
    ])
])

# Checks for header files
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([sasl/sasl.h], [], [
    AC_MSG_ERROR([SASL headers not found. Please install libsasl2-dev.])
])

AC_CHECK_HEADERS([sasl/saslplug.h], [], [
    AC_MSG_WARN([saslplug.h not found, some functionality may be limited])
])

AC_CHECK_HEADERS([sasl/plugin_common.h], [
    AC_DEFINE([HAVE_PLUGIN_COMMON_H], [1], [Define if you have plugin_common.h])
], [])

AC_CHECK_HEADERS([oauth2/oauth2.h], [], [
    AC_MSG_ERROR([liboauth2 headers not found. Please install liboauth2-dev.])
])

AC_CHECK_HEADERS([cjose/cjose.h], [], [
    AC_MSG_ERROR([libcjose headers not found. Please install libcjose-dev.])
])

AC_CHECK_HEADERS([jansson.h], [], [
    AC_MSG_ERROR([libjansson headers not found. Please install libjansson-dev.])
])

AC_CHECK_HEADERS([curl/curl.h], [], [
    AC_MSG_ERROR([libcurl headers not found. Please install libcurl4-openssl-dev.])
])

# Checks for typedefs, structures, and compiler characteristics
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strdup strndup strcasecmp strstr])

# Find SASL plugin directory
AC_ARG_WITH([sasl-plugindir],
    [AS_HELP_STRING([--with-sasl-plugindir=DIR], [SASL plugin directory])],
    [sasl_plugindir="$withval"],
    [sasl_plugindir=""])

if test "x$sasl_plugindir" = "x"; then
    # Try to detect SASL plugin directory
    PKG_CHECK_MODULES([SASL2], [libsasl2], [
        sasl_plugindir=`pkg-config --variable=plugindir libsasl2 2>/dev/null`
    ], [
        sasl_plugindir=""
    ])
    
    # If pkg-config didn't work, try common locations
    if test "x$sasl_plugindir" = "x"; then
        for dir in /usr/lib/sasl2 /usr/lib/x86_64-linux-gnu/sasl2 /usr/lib/aarch64-linux-gnu/sasl2 /usr/local/lib/sasl2 /usr/lib/*/sasl2; do
            if test -d "$dir"; then
                sasl_plugindir="$dir"
                AC_MSG_NOTICE([Found SASL plugin directory: $dir])
                break
            fi
        done
    fi
    
    # If still not found, use libsasl2 lib directory as fallback
    if test "x$sasl_plugindir" = "x"; then
        sasl_libdir=`pkg-config --variable=libdir libsasl2 2>/dev/null`
        if test "x$sasl_libdir" != "x"; then
            sasl_plugindir="$sasl_libdir/sasl2"
        fi
    fi
fi

if test "x$sasl_plugindir" = "x"; then
    AC_MSG_ERROR([Could not determine SASL plugin directory. Use --with-sasl-plugindir=DIR])
fi

AC_SUBST([sasl_plugindir])
AC_MSG_NOTICE([SASL plugin directory: $sasl_plugindir])

# Cyrus SASL configuration
AC_ARG_WITH([cyrus-sasl-prefix],
    [AS_HELP_STRING([--with-cyrus-sasl-prefix=PREFIX], [Cyrus SASL installation prefix])],
    [cyrus_sasl_prefix="$withval"],
    [cyrus_sasl_prefix=""])

if test "x$cyrus_sasl_prefix" != "x"; then
    CYRUS_SASL_CPPFLAGS="-I$cyrus_sasl_prefix/include"
    CYRUS_SASL_LDFLAGS="-L$cyrus_sasl_prefix/lib"
else
    CYRUS_SASL_CPPFLAGS=""
    CYRUS_SASL_LDFLAGS=""
fi

AC_SUBST([CYRUS_SASL_CPPFLAGS])
AC_SUBST([CYRUS_SASL_LDFLAGS])

# liboauth2 configuration
AC_ARG_WITH([oauth2-prefix],
    [AS_HELP_STRING([--with-oauth2-prefix=PREFIX], [liboauth2 installation prefix])],
    [oauth2_prefix="$withval"],
    [oauth2_prefix="/usr/local"])

if test "x$oauth2_prefix" != "x"; then
    OAUTH2_CPPFLAGS="-I$oauth2_prefix/include"
    OAUTH2_LDFLAGS="-L$oauth2_prefix/lib"
else
    OAUTH2_CPPFLAGS="-I/usr/local/include"
    OAUTH2_LDFLAGS="-L/usr/local/lib"
fi

# Check liboauth2 API version (oauth2_token_verify signature changed in 2.2.0)
AC_MSG_CHECKING([whether oauth2_token_verify uses 5 or 6 parameters])
save_CPPFLAGS="$CPPFLAGS"
save_CFLAGS="$CFLAGS"
save_LIBS="$LIBS"
CPPFLAGS="$CPPFLAGS $OAUTH2_CPPFLAGS"
CFLAGS="-c"
LIBS="$LIBS -loauth2 -ljansson"

# Try to compile with 6 parameters (new API >= 2.2.0)
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
        [[
#include <oauth2/oauth2.h>
#include <jansson.h>
        ]],
        [[
oauth2_log_t *log = (oauth2_log_t *)0;
oauth2_cfg_token_verify_t *verify = (oauth2_cfg_token_verify_t *)0;
const char *token = "test";
json_t *payload = (json_t *)0;
oauth2_http_status_code_t status_code = 0;
(void)oauth2_token_verify(log, (oauth2_http_request_t *)0, verify, token, &payload, &status_code);
        ]])],
    [
        AC_MSG_RESULT([6 parameters (liboauth2 >= 2.2.0)])
    ],
    [
        AC_MSG_RESULT([5 parameters (liboauth2 < 2.2.0)])
	OAUTH2_CPPFLAGS="$OAUTH2_CPPFLAGS -DLIBOAUTH2_OLD_API"
    ])

CPPFLAGS="$save_CPPFLAGS"
CFLAGS="$save_CFLAGS"
LIBS="$save_LIBS"

AC_SUBST([OAUTH2_CPPFLAGS])
AC_SUBST([OAUTH2_LDFLAGS])

# Debug build support
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [Enable debug build])],
    [debug_build="$enableval"],
    [debug_build="no"])

if test "x$debug_build" = "xyes"; then
    CFLAGS="$CFLAGS -g -O0 -DDEBUG -Wall -Wextra"
    AC_MSG_NOTICE([Debug build enabled])
else
    CFLAGS="$CFLAGS -O2 -DNDEBUG"
fi

# Tests build support
AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--disable-tests], [Disable building tests])],
    [build_tests="$enableval"],
    [build_tests="yes"])

AM_CONDITIONAL([BUILD_TESTS], [test "x$build_tests" = "xyes"])

if test "x$build_tests" = "xyes"; then
    AC_MSG_NOTICE([Tests will be built])
else
    AC_MSG_NOTICE([Tests disabled])
fi

# Feature flags
AC_DEFINE([OAUTH2_PLUGIN_VERSION], ["1.0.2"], [Plugin version])
AC_DEFINE([HAVE_LIBOAUTH2], [1], [Define if you have liboauth2])

AC_CONFIG_FILES([
    Makefile
])

AC_OUTPUT

echo
echo "Configuration Summary:"
echo "====================="
echo "Package:                 $PACKAGE_STRING"
echo "C Compiler:              $CC"
echo "CFLAGS:                  $CFLAGS"
echo "SASL Plugin Directory:   $sasl_plugindir"
echo "Cyrus SASL CPPFLAGS:     $CYRUS_SASL_CPPFLAGS"
echo "Cyrus SASL LDFLAGS:      $CYRUS_SASL_LDFLAGS"
echo "OAuth2 CPPFLAGS:         $OAUTH2_CPPFLAGS"
echo "OAuth2 LDFLAGS:          $OAUTH2_LDFLAGS"
echo "Debug Build:             $debug_build"
echo
