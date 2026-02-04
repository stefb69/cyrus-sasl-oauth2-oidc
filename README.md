# Cyrus SASL OAuth2/OIDC Plugin

A comprehensive SASL plugin for OAuth2 and OpenID Connect authentication, built with liboauth2 for native OIDC support.

## Features

- **Native OAuth2/OIDC Support**: Built on liboauth2 for comprehensive OAuth2 and OpenID Connect compliance
- **Automatic OIDC Discovery**: Automatically fetches provider metadata and JWKS
- **JWT Signature Verification**: Full JWT validation with signature verification using JWKS
- **Dual Mechanism Support**: Supports both XOAUTH2 and OAUTHBEARER SASL mechanisms
- **Built-in Cache Management**: Leverages liboauth2's comprehensive caching system
- **Multi-Provider Support**: Works with any standards-compliant OIDC provider
- **Security Focused**: Secure token handling with memory clearing and configurable SSL verification

## Supported Providers

- **Authentik** - Native support with automatic discovery
- **Keycloak** - Full compatibility with Keycloak OIDC
- **Azure AD** - Microsoft Azure Active Directory
- **Google Workspace** - Google OAuth2/OIDC
- **Okta** - Enterprise identity platform
- **Auth0** - Universal identity platform
- **Any OIDC-compliant provider**

## Installation

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install build-essential autotools-dev autoconf automake libtool
sudo apt-get install libsasl2-dev liboauth2-dev libcjose-dev libjansson-dev
sudo apt-get install libcurl4-openssl-dev libssl-dev

# RedHat/CentOS/Fedora
sudo yum install gcc autoconf automake libtool
sudo yum install cyrus-sasl-devel liboauth2-devel libcjose-devel jansson-devel
sudo yum install libcurl-devel openssl-devel
```

### Build and Install

```bash
# Optional: Install liboauth2 from source (required for plugin build, if no package available)
git clone https://github.com/OpenIDC/liboauth2.git /tmp/liboauth2 && \
cd /tmp/liboauth2 && \
./autogen.sh && \
./configure --with-apache=no --prefix=/usr/local && \
make && \
make install && \
ldconfig && \
cd / && \
rm -rf /tmp/liboauth2

# Clone or extract the source
cd cyrus-sasl-oauth2-oidc

# Generate build system
./autogen.sh

# Configure build
./configure

# Optional: Configure with custom paths
./configure \
    --with-sasl-plugindir=/usr/lib/x86_64-linux-gnu/sasl2 \
    --with-oauth2-prefix=/usr/local \
    --enable-debug

# Build and install
make
sudo make install

# Verify installation
ls -la /usr/lib/*/sasl2/lib*oauth*.so
```

## Supported Distributions

| Distribution | Version | Architecture | liboauth2 Version | Status |
|-------------|---------|--------------|-------------------|---------|
| Debian | Trixie (13) | AMD64, ARM64 | 2.x | ✅ Supported |
| Debian | Bookworm (12) | AMD64, ARM64 | 1.6.x | ✅ Supported |
| Ubuntu | 24.04 LTS (Noble) | AMD64, ARM64 | 1.6.0 | ✅ Supported |
| Ubuntu | 22.04 LTS (Jammy) | AMD64, ARM64 | N/A | ❌ No liboauth2 Package* |
| Fedora | 41+ | x86_64, aarch64 | 2.x | ✅ Supported |
| RHEL | 9 + EPEL | x86_64 | N/A | ❌ Not Compatible** |

*Ubuntu 22.04 LTS requires manual compilation of liboauth2 from source  
**RHEL 9 + EPEL lacks required dependencies (cjose, compatible liboauth2)

## Package Builds

This project supports building native packages for multiple Linux distributions.

### Debian Package Build (Trixie/Bookworm)

For Debian Trixie and Bookworm, you can build a native Debian package:

```bash
# Install build dependencies
sudo apt-get install debhelper-compat autotools-dev autoconf automake libtool pkg-config
sudo apt-get install libsasl2-dev liboauth2-dev libcjose-dev libjansson-dev
sudo apt-get install libcurl4-openssl-dev libssl-dev

# Build the package
dpkg-buildpackage -us -uc -b

# Install the generated package
sudo dpkg -i ../cyrus-sasl-oauth2-oidc_1.0.0-1_amd64.deb

# Fix any missing dependencies
sudo apt-get install -f
```

The Debian package includes:
- Proper integration with SASL plugin directory
- Automatic library dependency resolution
- Post-installation scripts for SASL daemon restart
- Standard Debian package metadata and documentation

### Ubuntu Package Build (24.04 LTS)

For Ubuntu 24.04 LTS (Noble):

```bash
# Install build dependencies
sudo apt update
sudo apt install build-essential debhelper devscripts fakeroot lintian
sudo apt install pkg-config libtool autoconf automake autotools-dev
sudo apt install libsasl2-dev liboauth2-dev libcjose-dev libjansson-dev
sudo apt install libcurl4-openssl-dev libssl-dev

# Build the package
dpkg-buildpackage -us -uc -b

# Install the package
sudo dpkg -i ../cyrus-sasl-oauth2-oidc_1.0.0-1_amd64.deb
sudo apt-get install -f  # Fix dependencies if needed
```

The Ubuntu package includes:
- Integration with standard SASL plugin directory (`/usr/lib/*/sasl2/`)
- Automatic dependency resolution via APT
- Post-installation scripts for SASL daemon restart
- Compatible with Ubuntu 24.04 LTS (Noble) with liboauth2 1.6.0

**Note**: Ubuntu 22.04 LTS (Jammy) is not supported due to missing liboauth2 packages in official repositories.

### RPM Package Build (Fedora)

For Fedora distributions:

```bash
# Fedora - Install build dependencies
sudo dnf install rpm-build rpmdevtools gcc make autoconf automake libtool pkgconfig
sudo dnf install cyrus-sasl-devel liboauth2-devel libcjose-devel jansson-devel
sudo dnf install libcurl-devel openssl-devel

# Note: RHEL/CentOS/Rocky/Alma Linux are not currently supported
# due to missing dependencies (liboauth2-devel, cjose-devel) in EPEL repositories

# Set up RPM build environment
rpmdev-setuptree

# Create source tarball
tar -czf ~/rpmbuild/SOURCES/cyrus-sasl-oauth2-oidc-1.0.0.tar.gz .

# Copy spec file
cp rpm/cyrus-sasl-oauth2-oidc.spec ~/rpmbuild/SPECS/

# Build RPM
rpmbuild -ba ~/rpmbuild/SPECS/cyrus-sasl-oauth2-oidc.spec

# Install the generated package
sudo dnf install ~/rpmbuild/RPMS/x86_64/cyrus-sasl-oauth2-oidc-1.0.0-1.*.x86_64.rpm
```

The RPM package includes:
- Integration with standard SASL plugin directory (`/usr/lib*/sasl2/`)
- Automatic dependency resolution via RPM
- Post-installation scripts for ldconfig and service restart
- Compatible with Fedora 41+

**Note**: RHEL/CentOS/Rocky/Alma Linux are not currently supported due to missing OAuth2 dependencies in EPEL repositories.

### Docker-based Package Building

For automated builds with proper isolation:

```bash
# Build Debian packages
./build-packages.sh debian trixie packages amd64     # Trixie AMD64
./build-packages.sh debian trixie packages arm64     # Trixie ARM64
./build-packages.sh debian bookworm packages amd64   # Bookworm AMD64
./build-packages.sh debian bookworm packages arm64   # Bookworm ARM64

# Build Ubuntu packages
./build-packages.sh ubuntu 24.04 packages amd64      # Ubuntu 24.04 LTS AMD64
./build-packages.sh ubuntu 24.04 packages arm64      # Ubuntu 24.04 LTS ARM64

# Build Fedora packages  
./build-packages.sh fedora 41 packages x86_64       # x86_64
./build-packages.sh fedora 41 packages aarch64      # ARM64

# Test package installation
./build-packages.sh debian trixie test amd64        # Test Debian Trixie
./build-packages.sh debian bookworm test amd64      # Test Debian Bookworm
./build-packages.sh fedora 41 test x86_64           # Test Fedora
```

Built packages will be available in the `packages/` directory.

## Configuration

### ⚠️ **IMPORTANT: Configuration Format Differences**

The OAuth2 SASL plugin configuration format **depends on the application** you're configuring:

#### **Cyrus IMAP Server** (uses `sasl_` prefix)
- Configuration file: `/etc/imapd.conf` or `/etc/cyrus.conf`
- Option format: `sasl_oauth2_option_name: value`
- **Cyrus IMAP adds `sasl_` prefix** to all SASL options in its main configuration files

#### **Other SASL Applications** (NO prefix)
- Configuration files: `/etc/sasl2/appname.conf` (e.g., `/etc/sasl2/smtpd.conf`)
- Option format: `oauth2_option_name: value`
- **Standard SASL applications use plain option names** in their dedicated SASL configuration files

#### **Side-by-Side Comparison**

| Application Type | Config File Location | Option Format | Example |
|-----------------|---------------------|---------------|---------|
| **Cyrus IMAP** | `/etc/imapd.conf` | `sasl_oauth2_*` | `sasl_oauth2_discovery_url: https://...` |
| **Dovecot** | `/etc/sasl2/dovecot.conf` | `oauth2_*` | `oauth2_discovery_url: https://...` |
| **Sendmail** | `/etc/sasl2/Sendmail.conf` | `oauth2_*` | `oauth2_discovery_url: https://...` |

**⚠️ Common Mistake**: Using `sasl_oauth2_*` options in `/etc/sasl2/` files will **NOT work** - only plain `oauth2_*` options work there.

### Basic Configuration

The plugin is configured through SASL configuration files or application-specific settings.

#### **For Cyrus IMAP Server** (with `sasl_` prefix)

**Method 1: OIDC Discovery URL (Recommended)**

```ini
# /etc/imapd.conf (Cyrus IMAP configuration)
sasl_oauth2_discovery_url: https://your-provider.com/.well-known/openid-configuration
sasl_oauth2_client_id: your-client-id
sasl_oauth2_audience: your-audience
```

**Method 2: Manual Issuer Configuration**

```ini
# /etc/imapd.conf (Cyrus IMAP configuration)
sasl_oauth2_issuer: https://your-provider.com/
sasl_oauth2_client_id: your-client-id
sasl_oauth2_audience: your-audience
```

#### **For Other SASL Applications** (NO prefix)

**Method 1: OIDC Discovery URL (Recommended)**

```ini
# /etc/sasl2/appname.conf (e.g., smtpd.conf, dovecot.conf)
oauth2_discovery_url: https://your-provider.com/.well-known/openid-configuration
oauth2_client_id: your-client-id
oauth2_audience: your-audience
```

**Method 2: Manual Issuer Configuration**

```ini
# /etc/sasl2/appname.conf (e.g., smtpd.conf, dovecot.conf)
oauth2_issuer: https://your-provider.com/
oauth2_client_id: your-client-id
oauth2_audience: your-audience
```

### Complete Configuration Reference

```ini
# === Core OIDC Settings ===
# Single OIDC Discovery URL (auto-discovers all endpoints)
sasl_oauth2_discovery_url: https://id.example.com/.well-known/openid-configuration

# OR multiple discovery URLs (space-separated)
sasl_oauth2_discovery_urls: https://id1.example.com/.well-known/openid-configuration https://id2.example.com/.well-known/openid-configuration

# OR manually specify single issuer (discovery URL will be constructed)
sasl_oauth2_issuer: https://id.example.com/

# OR multiple issuers (space-separated)
sasl_oauth2_issuers: https://id1.example.com/ https://id2.example.com/

# OAuth2 Client Credentials
sasl_oauth2_client_id: your-client-id
sasl_oauth2_client_secret: your-client-secret

# === Token Validation ===
# Expected audience in JWT tokens (single)
sasl_oauth2_audience: your-service-audience

# OR multiple audiences (space-separated)
sasl_oauth2_audiences: audience1 audience2 audience3

# Required scope in JWT tokens
sasl_oauth2_scope: openid email profile

# JWT claim containing username (default: email)
sasl_oauth2_user_claim: email

# Verify JWT signature with JWKS (default: yes)
sasl_oauth2_verify_signature: yes

# === Debug and Logging ===
# Enable debug logging for OAuth2 operations (default: no)
sasl_oauth2_debug: no

# === Network Settings ===
# Verify SSL certificates (default: yes)
sasl_oauth2_ssl_verify: yes

# HTTP timeout in seconds (default: 10)
sasl_oauth2_timeout: 10

# === SASL Mechanism Selection ===
# Enable OAuth2 mechanisms
sasl_mech_list: oauthbearer xoauth2 plain login

# === Fallback Configuration File ===
# Path to fallback configuration file (default: /etc/sasl2/oauth2.conf)
# Used when no OAuth2 configuration is found in application config
sasl_oauth2_fallback_config: /etc/sasl2/oauth2.conf
```

### Fallback Configuration File

The plugin supports a fallback configuration file that provides default OAuth2 settings when applications don't have their own OAuth2 configuration. This is particularly useful for SASL tools like `saslauthd`, `pluginviewer`, and `imtest` that don't have dedicated configuration files and for applications like Postfix that read only a subset of SASL configurations.

**Default Location**: `/etc/sasl2/oauth2.conf`

**How It Works**:
1. Plugin attempts to load OAuth2 configuration from the application's SASL config
2. If no OAuth2 configuration is found, it checks the fallback config file
3. If the fallback file exists and contains valid OAuth2 settings, those are used
4. If neither source provides configuration, the plugin remains inactive

**Example Fallback Configuration File** (`/etc/sasl2/oauth2.conf`):

```ini
# OAuth2/OIDC SASL Plugin - Fallback Configuration
oauth2_discovery_url: https://your-provider.com/.well-known/openid-configuration
oauth2_client_id: your-client-id
oauth2_audience: your-audience
```

**Custom Fallback Path**:

You can specify a custom fallback configuration path in any application's SASL config:

```ini
# In /etc/sasl2/appname.conf or /etc/imapd.conf
oauth2_fallback_config: /etc/sasl2/custom-oauth2.conf
# OR with sasl_ prefix for Cyrus IMAP
sasl_oauth2_fallback_config: /etc/sasl2/custom-oauth2.conf
```

**Benefits**:
- ✅ SASL tools work without errors even when OAuth2 is not configured for them
- ✅ Single configuration file can provide defaults for all SASL applications
- ✅ Application-specific configs always take precedence over fallback
- ✅ Optional - existing installations are not affected

See `oauth2.conf.example` for a complete example fallback configuration file.

## Multi-Provider Configuration

The plugin supports multiple OAuth2 providers simultaneously through space-separated configuration lists:

### Multi-Application Setup (Authentik)

```ini
# /etc/sasl2/imapd.conf - Multiple Authentik applications
sasl_oauth2_discovery_urls: https://auth.example.com/application/o/cyrus-imapd/.well-known/openid-configuration https://auth.example.com/application/o/roundcube/.well-known/openid-configuration
sasl_oauth2_audiences: cyrus-client-id roundcube-client-id
sasl_oauth2_client_id: cyrus-client-id
sasl_oauth2_user_claim: email
sasl_oauth2_scope: openid email profile
```

### Multi-Provider Setup (Mixed)

```ini
# /etc/sasl2/imapd.conf - Authentik + Keycloak
sasl_oauth2_discovery_urls: https://auth.example.com/application/o/cyrus/.well-known/openid-configuration https://keycloak.example.com/realms/mail/.well-known/openid-configuration
sasl_oauth2_audiences: wizzz-cyrus-client keycloak-cyrus-client
sasl_oauth2_client_id: primary-client-id
sasl_oauth2_user_claim: email
```

### Multiple Provider Failover

```ini
# Primary and backup providers
sasl_oauth2_issuers: https://primary-auth.example.com/ https://backup-auth.example.com/
sasl_oauth2_audiences: service-audience
sasl_oauth2_client_id: shared-client-id
```

## Provider-Specific Examples

### Authentik Configuration

```ini
# /etc/sasl2/imapd.conf - Authentik with application-level OIDC
sasl_oauth2_discovery_url: https://auth.example.com/application/o/cyrus-imapd/.well-known/openid-configuration
sasl_oauth2_client_id: eJZOYBRL8eq8gQOHevY0E2EIXkQtW0McHMSkspy7
sasl_oauth2_audience: eJZOYBRL8eq8gQOHevY0E2EIXkQtW0McHMSkspy7
sasl_oauth2_user_claim: email
sasl_oauth2_scope: openid email profile
sasl_oauth2_verify_signature: yes
```

### Keycloak Configuration

```ini
# /etc/sasl2/imapd.conf - Keycloak
sasl_oauth2_discovery_url: https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration
sasl_oauth2_client_id: cyrus-imap-client
sasl_oauth2_audience: cyrus-imap
sasl_oauth2_user_claim: preferred_username
sasl_oauth2_scope: openid email profile
```

### Azure AD Configuration

```ini
# /etc/sasl2/imapd.conf - Azure AD
sasl_oauth2_discovery_url: https://login.microsoftonline.com/your-tenant-id/v2.0/.well-known/openid-configuration
sasl_oauth2_client_id: your-azure-app-id
sasl_oauth2_audience: your-azure-app-id
sasl_oauth2_user_claim: email
sasl_oauth2_scope: openid email profile
```

### Google Workspace Configuration

```ini
# /etc/sasl2/imapd.conf - Google
sasl_oauth2_discovery_url: https://accounts.google.com/.well-known/openid-configuration
sasl_oauth2_client_id: your-google-client-id.apps.googleusercontent.com
sasl_oauth2_audience: your-google-client-id.apps.googleusercontent.com
sasl_oauth2_user_claim: email
sasl_oauth2_scope: openid email profile
```

## Application Integration

### Cyrus IMAP Integration

```ini
# /etc/cyrus.conf - Service configuration
SERVICES {
    imap          cmd="imapd" listen="imap" prefork=0
    imaps         cmd="imapd -s" listen="imaps" prefork=0
    pop3          cmd="pop3d" listen="pop3" prefork=0
    pop3s         cmd="pop3d -s" listen="pop3s" prefork=0
    sieve         cmd="timsieved" listen="sieve" prefork=0
}

# /etc/imapd.conf - IMAP configuration
sasl_mech_list: oauthbearer xoauth2 plain login
sasl_oauth2_discovery_url: https://your-provider.com/.well-known/openid-configuration
sasl_oauth2_client_id: your-client-id
sasl_oauth2_audience: your-audience
```

### Postfix Integration

**⚠️ IMPORTANT**: Postfix uses SASL configuration files **WITHOUT** the `sasl_` prefix.

**⚠️ IMPORTANT**: https://www.postfix.org/SASL_README.html
                 "This means that some SASL-related configuration files will belong to 
                  Postfix, while other configuration files belong to the specific SASL 
                  implementation that Postfix will use."

Oauth2 is a specific SASL implementation and its configuration belongs to /etc/sasl2/oauth2.conf.

```ini
# /etc/postfix/main.cf
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = cyrus
smtpd_sasl_path = smtpd
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = example.com

# /etc/sasl2/smtpd.conf - SASL plugin configuration (NO sasl_ prefix!)
mech_list: oauthbearer xoauth2 plain login

# /etc/sasl2/oauth2.conf
oauth2_discovery_url: https://your-provider.com/.well-known/openid-configuration
oauth2_client_id: your-smtp-client-id
oauth2_audience: your-smtp-audience
oauth2_user_claim: email
oauth2_scope: openid email profile
```

### Dovecot Integration

**⚠️ IMPORTANT**: Dovecot uses SASL configuration files **WITHOUT** the `sasl_` prefix.

```ini
# /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = oauthbearer xoauth2 plain login
auth_username_format = %Lu

# Enable SASL authentication for Dovecot
passdb {
  driver = sasl
  mechanisms = oauthbearer xoauth2
}

# /etc/sasl2/dovecot.conf - SASL plugin configuration (NO sasl_ prefix!)
oauth2_discovery_url: https://your-provider.com/.well-known/openid-configuration
oauth2_client_id: your-dovecot-client-id
oauth2_audience: your-dovecot-audience
oauth2_user_claim: email
oauth2_scope: openid email profile
mech_list: oauthbearer xoauth2 plain login
```

## Testing and Troubleshooting

### Testing with OpenSSL s_client

```bash
# Test IMAP with XOAUTH2
openssl s_client -connect mail.example.com:993 -crlf

# In the IMAP session:
a001 AUTHENTICATE XOAUTH2
# Paste base64-encoded XOAUTH2 string: base64("user=user@example.com\x01auth=Bearer YOUR_ACCESS_TOKEN\x01\x01")

# Test SMTP with OAUTHBEARER  
openssl s_client -connect mail.example.com:587 -starttls smtp -crlf

# In the SMTP session:
AUTH OAUTHBEARER
# Paste OAUTHBEARER string: n,a=user@example.com,\x01auth=Bearer YOUR_ACCESS_TOKEN\x01\x01
```

### Common Configuration Issues

#### 0. Wrong Configuration Prefix (Most Common Error)

**Problem**: Using `sasl_oauth2_*` options in `/etc/sasl2/` files or using plain `oauth2_*` options in Cyrus IMAP files.

**Symptoms**:
```
sasl_plugin: Plugin configuration not found
oauth2_plugin: Configuration option not recognized
Authentication failed: no mechanism available
```

**Solution**: Use the correct prefix format:
- **Cyrus IMAP**: Use `sasl_oauth2_*` in `/etc/imapd.conf`
- **All other apps**: Use `oauth2_*` in `/etc/sasl2/appname.conf`

**Incorrect Examples**:
```ini
# ❌ WRONG: Using sasl_ prefix in /etc/sasl2/smtpd.conf
sasl_oauth2_discovery_url: https://provider.com/.well-known/openid-configuration

# ❌ WRONG: Using plain options in /etc/imapd.conf  
oauth2_discovery_url: https://provider.com/.well-known/openid-configuration
```

**Correct Examples**:
```ini
# ✅ CORRECT: Plain options in /etc/sasl2/smtpd.conf
oauth2_discovery_url: https://provider.com/.well-known/openid-configuration

# ✅ CORRECT: sasl_ prefix in /etc/imapd.conf
sasl_oauth2_discovery_url: https://provider.com/.well-known/openid-configuration
```

#### 1. Plugin Not Loading

```bash
# Check if plugin is installed
ls -la /usr/lib/*/sasl2/lib*oauth*.so

# Check SASL plugin path
saslauthd -V
sasldblistusers2

# Test SASL mechanisms
saslpluginviewer
```

#### 2. OIDC Discovery Issues

```bash
# Test OIDC discovery endpoint
curl -v https://your-provider.com/.well-known/openid-configuration

# Check JWKS endpoint
curl -v https://your-provider.com/.well-known/jwks

# Verify SSL certificates
openssl s_client -connect your-provider.com:443 -servername your-provider.com
```

#### 3. JWT Token Issues

```bash
# Decode JWT token (without verification)
echo "YOUR_JWT_TOKEN" | cut -d. -f2 | base64 -d | jq .

# Check token claims
# Ensure 'iss', 'aud', 'exp', 'nbf' claims are correct
# Verify username claim matches expected format
```

### Debug Logging

Enable debug logging in your SASL configuration:

```ini
# Add to your SASL config file
log_level: 7
sasl_oauth2_debug: yes
```

The `sasl_oauth2_debug` option controls the verbosity of liboauth2 logs:
- `sasl_oauth2_debug: no` (default) - Only errors and warnings
- `sasl_oauth2_debug: yes` - Detailed debug traces including cache operations, HTTP requests, and JWT validation steps

Check system logs:
```bash
# System logs
journalctl -u cyrus-imapd -f
tail -f /var/log/mail.log

# SASL-specific logs
tail -f /var/log/auth.log | grep sasl
```

### Log Messages

**Successful Authentication:**
```
oauth2_plugin: Configuration loaded successfully
oauth2_plugin: JWT token validation successful for user: user@example.com
oauth2_plugin: OAuth2 authentication successful for user: user@example.com
```

**Common Error Messages:**
```
oauth2_plugin: Failed to get OIDC metadata for issuer: https://provider.com
oauth2_plugin: JWT signature verification failed: Invalid signature
oauth2_plugin: Token audience 'wrong-aud' does not match expected 'correct-aud'
oauth2_plugin: Token username 'user@example.com' does not match expected 'different@example.com'
oauth2_plugin: JWT token has expired
```

## Security Considerations

### Token Security
- Access tokens are cleared from memory after authentication
- JWT signatures are verified by default using JWKS
- SSL certificate verification is enabled by default
- Configurable timeout prevents hanging connections

### Network Security
```ini
# Recommended security settings
sasl_oauth2_ssl_verify: yes
sasl_oauth2_verify_signature: yes
sasl_oauth2_timeout: 10
```

### Caching Security
- liboauth2 manages caching internally with secure defaults
- Cache data is automatically cleaned up and secured
- No manual cache configuration required

## Performance Tuning

### Performance Optimization

The plugin uses liboauth2's built-in caching system which automatically handles:
- OIDC metadata and JWKS caching
- Token validation result caching
- HTTP request optimization

```ini
# For production environments, consider:
sasl_oauth2_timeout: 5              # Faster timeouts for responsive providers
sasl_oauth2_ssl_verify: yes         # Always verify SSL in production
sasl_oauth2_verify_signature: yes   # Always verify JWT signatures
```



## Migration from SciTokens Plugin

If migrating from the existing SciTokens-based plugin:

### Configuration Changes

```ini
# OLD (SciTokens-based)
sasl_xoauth2_issuers: https://id.example.com/application/o/app/
sasl_xoauth2_aud: client-id
sasl_xoauth2_user_claim: email

# NEW (liboauth2-based)
sasl_oauth2_discovery_url: https://id.example.com/application/o/app/.well-known/openid-configuration
sasl_oauth2_client_id: client-id
sasl_oauth2_audience: client-id
sasl_oauth2_user_claim: email
```

### Benefits of Migration

- **Native OIDC Support**: No more fallback mechanisms needed
- **Better Performance**: Uses liboauth2's optimized caching and HTTP client
- **Enhanced Security**: Full JWT signature verification with JWKS
- **Broader Compatibility**: Works with all OIDC providers out of the box
- **Simplified Configuration**: Single discovery URL instead of multiple endpoints
- **Better Maintenance**: Active liboauth2 development and community support
- **Debug Control**: Configurable logging levels for troubleshooting

## Development and Contributing

### Building from Source

```bash
git clone https://github.com/your-org/cyrus-sasl-oauth2-oidc.git
cd cyrus-sasl-oauth2-oidc
./autogen.sh
./configure --enable-debug
make
make check-syntax
```

### Testing

```bash
# Syntax check
make check-syntax

# Manual testing
make install-debug
# Configure test environment
# Test with various providers
```

## License

This plugin is licensed under the MIT License. See the LICENSE file for details.

## Support

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Additional documentation available in the `docs/` directory
- **Community**: Join our discussion forum for support and questions

## Changelog

### Version 1.0.0
- Initial release with liboauth2 integration
- Support for XOAUTH2 and OAUTHBEARER mechanisms
- Automatic OIDC discovery
- JWT signature verification with JWKS
- Built-in cache management via liboauth2
- Multi-provider support
- Configurable debug logging (`sasl_oauth2_debug` option)
- Simplified architecture with redundant cache system removed
- Enhanced JWT validation using `oauth2_token_verify`
