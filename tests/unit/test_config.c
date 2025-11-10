#include "test_framework.h"
#include "mock_sasl.h"
#include "../../oauth2_plugin.h"
#include <string.h>

/* Forward declarations for functions we need to test */
extern char **oauth2_parse_string_list(const char *input, int *count);
extern void oauth2_free_string_list(char **list, int count);

/* Test string list parsing */
int test_parse_string_list() {
    int count = 0;
    
    /* Test single item */
    char **result = oauth2_parse_string_list("single_item", &count);
    TEST_ASSERT_NOT_NULL(result, "Should parse single item successfully");
    TEST_ASSERT(count == 1, "Should have one item");
    TEST_ASSERT_NOT_NULL(result[0], "First item should not be NULL");
    TEST_ASSERT_STR_EQ("single_item", result[0], "Item should match");
    
    /* Cleanup */
    oauth2_free_string_list(result, count);
    
    /* Test multiple items */
    result = oauth2_parse_string_list("item1 item2 item3", &count);
    TEST_ASSERT_NOT_NULL(result, "Should parse multiple items successfully");
    TEST_ASSERT(count == 3, "Should have three items");
    TEST_ASSERT_NOT_NULL(result[0], "First item should not be NULL");
    TEST_ASSERT_NOT_NULL(result[1], "Second item should not be NULL");
    TEST_ASSERT_NOT_NULL(result[2], "Third item should not be NULL");
    TEST_ASSERT_STR_EQ("item1", result[0], "First item should match");
    TEST_ASSERT_STR_EQ("item2", result[1], "Second item should match");
    TEST_ASSERT_STR_EQ("item3", result[2], "Third item should match");
    
    /* Cleanup */
    oauth2_free_string_list(result, count);
    
    /* Test empty string */
    result = oauth2_parse_string_list("", &count);
    TEST_ASSERT_NULL(result, "Result should be NULL for empty input");
    TEST_ASSERT(count == 0, "Should have zero items for empty input");
    
    /* Test NULL input */
    result = oauth2_parse_string_list(NULL, &count);
    TEST_ASSERT_NULL(result, "Result should be NULL for NULL input");
    TEST_ASSERT(count == 0, "Should have zero items for NULL input");
    
    return 0;
}

/* Test string list parsing with extra spaces */
int test_parse_string_list_spaces() {
    int count = 0;
    
    /* Test with leading/trailing spaces */
    char **result = oauth2_parse_string_list("  item1  item2  item3  ", &count);
    TEST_ASSERT_NOT_NULL(result, "Should parse items with extra spaces successfully");
    TEST_ASSERT(count == 3, "Should have three items");
    TEST_ASSERT_STR_EQ("item1", result[0], "First item should match");
    TEST_ASSERT_STR_EQ("item2", result[1], "Second item should match");
    TEST_ASSERT_STR_EQ("item3", result[2], "Third item should match");
    
    /* Cleanup */
    oauth2_free_string_list(result, count);
    
    /* Test with multiple spaces between items */
    result = oauth2_parse_string_list("item1  item2   item3", &count);
    TEST_ASSERT_NOT_NULL(result, "Should parse items with multiple spaces successfully");
    TEST_ASSERT(count == 3, "Should have three items");
    TEST_ASSERT_STR_EQ("item1", result[0], "First item should match");
    TEST_ASSERT_STR_EQ("item2", result[1], "Second item should match");
    TEST_ASSERT_STR_EQ("item3", result[2], "Third item should match");
    
    /* Cleanup */
    oauth2_free_string_list(result, count);
    
    return 0;
}

/* Test config parsing */
int test_config_parsing() {
    /* Clear any existing config */
    mock_config_clear();
    
    /* Test setting and getting a string value */
    const char *plugin_name = "OAUTH2";
    const char *test_key = "test_key";
    const char *test_value = "test_value";
    
    mock_config_set(plugin_name, test_key, test_value);
    
    const char *retrieved;
    int ret = mock_getopt(NULL, plugin_name, test_key, &retrieved, NULL);
    TEST_ASSERT(ret == SASL_OK, "Should retrieve value successfully");
    TEST_ASSERT_NOT_NULL(retrieved, "Should retrieve value");
    TEST_ASSERT_STR_EQ(test_value, retrieved, "Retrieved value should match");
    
    /* Test getting non-existent key */
    ret = mock_getopt(NULL, plugin_name, "non_existent_key", &retrieved, NULL);
    TEST_ASSERT(ret != SASL_OK, "Should fail for non-existent key");
    TEST_ASSERT_NULL(retrieved, "Should return NULL for non-existent key");
    
    /* Test setting multiple values */
    mock_config_set(plugin_name, "key1", "value1");
    mock_config_set(plugin_name, "key2", "value2");
    mock_config_set(plugin_name, "key3", "value3");
    
    ret = mock_getopt(NULL, plugin_name, "key1", &retrieved, NULL);
    TEST_ASSERT(ret == SASL_OK, "Should retrieve first value successfully");
    TEST_ASSERT_STR_EQ("value1", retrieved, "First value should match");
    
    ret = mock_getopt(NULL, plugin_name, "key2", &retrieved, NULL);
    TEST_ASSERT(ret == SASL_OK, "Should retrieve second value successfully");
    TEST_ASSERT_STR_EQ("value2", retrieved, "Second value should match");
    
    ret = mock_getopt(NULL, plugin_name, "key3", &retrieved, NULL);
    TEST_ASSERT(ret == SASL_OK, "Should retrieve third value successfully");
    TEST_ASSERT_STR_EQ("value3", retrieved, "Third value should match");
    
    return 0;
}

/* Test config parsing with string lists */
int test_config_string_lists() {
    /* Clear any existing config */
    mock_config_clear();
    
    /* Test setting and parsing issuer list */
    const char *plugin_name = "OAUTH2";
    const char *issuers_key = OAUTH2_CONF_ISSUERS;
    const char *issuers_value = "https://issuer1.com https://issuer2.com https://issuer3.com";
    
    mock_config_set(plugin_name, issuers_key, issuers_value);
    
    const char *retrieved;
    int ret = mock_getopt(NULL, plugin_name, issuers_key, &retrieved, NULL);
    TEST_ASSERT(ret == SASL_OK, "Should retrieve issuers successfully");
    TEST_ASSERT_NOT_NULL(retrieved, "Should retrieve issuers");
    TEST_ASSERT_STR_EQ(issuers_value, retrieved, "Retrieved issuers should match");
    
    /* Test setting and parsing audience list */
    const char *audiences_key = OAUTH2_CONF_AUDIENCES;
    const char *audiences_value = "aud1 aud2 aud3";
    
    mock_config_set(plugin_name, audiences_key, audiences_value);
    
    ret = mock_getopt(NULL, plugin_name, audiences_key, &retrieved, NULL);
    TEST_ASSERT(ret == SASL_OK, "Should retrieve audiences successfully");
    TEST_ASSERT_NOT_NULL(retrieved, "Should retrieve audiences");
    TEST_ASSERT_STR_EQ(audiences_value, retrieved, "Retrieved audiences should match");
    
    return 0;
}

/* Test memory allocation tracking */
int test_memory_tracking() {
    /* Reset counters */
    mock_reset_malloc_counts();
    
    /* Allocate some memory */
    void *ptr1 = mock_malloc(100);
    TEST_ASSERT_NOT_NULL(ptr1, "Should allocate memory successfully");
    
    void *ptr2 = mock_malloc(200);
    TEST_ASSERT_NOT_NULL(ptr2, "Should allocate memory successfully");
    
    /* Check allocation count */
    TEST_ASSERT(mock_get_malloc_count() == 2, "Should have 2 allocations");
    
    /* Free memory */
    mock_free(ptr1);
    mock_free(ptr2);
    
    /* Check that all memory was freed */
    TEST_ASSERT(mock_get_malloc_count() == mock_get_free_count(), 
                "All allocated memory should be freed");
    
    return 0;
}

/* Test config validation */
int test_config_validation() {
    /* Test valid configuration */
    mock_config_clear();
    mock_config_set("OAUTH2", OAUTH2_CONF_ISSUERS, "https://issuer.com");
    mock_config_set("OAUTH2", OAUTH2_CONF_AUDIENCES, "audience1");
    
    /* This would normally call the validation function */
    const char *issuer, *aud;
    int ret1 = mock_getopt(NULL, "OAUTH2", OAUTH2_CONF_ISSUERS, &issuer, NULL);
    int ret2 = mock_getopt(NULL, "OAUTH2", OAUTH2_CONF_AUDIENCES, &aud, NULL);
    TEST_ASSERT(ret1 == SASL_OK && ret2 == SASL_OK, "Should have config values");
    TEST_ASSERT_NOT_NULL(issuer, "Should have issuer");
    TEST_ASSERT_NOT_NULL(aud, "Should have audience");
    
    /* Test configuration with multiple issuers and audiences */
    mock_config_clear();
    mock_config_set("OAUTH2", OAUTH2_CONF_ISSUERS, "https://issuer1.com https://issuer2.com");
    mock_config_set("OAUTH2", OAUTH2_CONF_AUDIENCES, "aud1 aud2 aud3");
    
    ret1 = mock_getopt(NULL, "OAUTH2", OAUTH2_CONF_ISSUERS, &issuer, NULL);
    ret2 = mock_getopt(NULL, "OAUTH2", OAUTH2_CONF_AUDIENCES, &aud, NULL);
    TEST_ASSERT(ret1 == SASL_OK && ret2 == SASL_OK, "Should have config values");
    TEST_ASSERT_NOT_NULL(issuer, "Should have issuers");
    TEST_ASSERT_NOT_NULL(aud, "Should have audiences");
    
    return 0;
}

/* Test edge cases */
int test_config_edge_cases() {
    /* Test very long string */
    mock_config_clear();
    char long_string[1000];
    memset(long_string, 'a', 999);
    long_string[999] = '\0';
    
    mock_config_set("OAUTH2", "long_key", long_string);
    const char *retrieved;
    int ret = mock_getopt(NULL, "OAUTH2", "long_key", &retrieved, NULL);
    TEST_ASSERT(ret == SASL_OK, "Should handle long strings successfully");
    TEST_ASSERT_NOT_NULL(retrieved, "Should handle long strings");
    TEST_ASSERT_STR_EQ(long_string, retrieved, "Long string should match");
    
    /* Test special characters */
    mock_config_clear();
    const char *special_chars = "test:value;with@special#chars";
    mock_config_set("OAUTH2", "special_key", special_chars);
    ret = mock_getopt(NULL, "OAUTH2", "special_key", &retrieved, NULL);
    TEST_ASSERT(ret == SASL_OK, "Should handle special characters successfully");
    TEST_ASSERT_NOT_NULL(retrieved, "Should handle special characters");
    TEST_ASSERT_STR_EQ(special_chars, retrieved, "Special characters should match");
    
    return 0;
}

/* Test missing configuration handling */
int test_missing_configuration() {
    /* Reset config to simulate no OAuth2 configuration */
    mock_config_clear();
    
    /* Test that oauth2_config_load handles missing configuration gracefully */
    sasl_utils_t utils = {
        .getopt = mock_getopt,
        .malloc = mock_malloc,
        .free = mock_free,
        .getopt_context = NULL,
        .conn = NULL,
        .log = mock_log,
        .seterror = mock_seterror
    };
    
    oauth2_config_t *config = oauth2_config_init(&utils);
    TEST_ASSERT_NOT_NULL(config, "Should initialize config structure");
    
    int result = oauth2_config_load(config, &utils);
    TEST_ASSERT(result == OAUTH2_CONFIG_NOT_FOUND, "Should return CONFIG_NOT_FOUND for missing config");
    TEST_ASSERT(config->configured == 0, "Should mark config as not configured");
    
    oauth2_config_free(config);
    
    /* Test partial configuration (discovery URL but no client_id) should still mark as configured */
    mock_config_clear();
    mock_config_set("OAUTH2", OAUTH2_CONF_DISCOVERY_URL, "https://provider.com/.well-known/openid-configuration");
    
    config = oauth2_config_init(&utils);
    TEST_ASSERT_NOT_NULL(config, "Should initialize config structure");
    
    result = oauth2_config_load(config, &utils);
    TEST_ASSERT(result == SASL_FAIL, "Should fail for invalid config (missing client_id)");
    
    oauth2_config_free(config);
    
    return 0;
}

/* Main test runner for config tests */
int main() {
    tests_total = 0;
    tests_passed = 0;
    tests_failed = 0;
    
    printf("Running OAuth2 Config Unit Tests\n");
    printf("===============================\n");
    
    RUN_TEST(test_parse_string_list);
    RUN_TEST(test_parse_string_list_spaces);
    RUN_TEST(test_config_parsing);
    RUN_TEST(test_config_string_lists);
    RUN_TEST(test_memory_tracking);
    RUN_TEST(test_config_validation);
    RUN_TEST(test_config_edge_cases);
    RUN_TEST(test_missing_configuration);
    
    printf("\nResults: %d/%d tests passed (%d failed)\n", 
           tests_passed, tests_total, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}
