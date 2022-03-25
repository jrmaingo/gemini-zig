#include "shim.h"

#include <mbedtls/ssl.h>

size_t mbedtls_ssl_config_size = sizeof(mbedtls_ssl_config);
