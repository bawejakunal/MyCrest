#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

size_t calcDecodeLength(const char* b64input);

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length);

int Base64Encode(unsigned char* buffer, size_t length, char** b64text);