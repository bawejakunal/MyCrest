#include "bgw.h"
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

// Just for convenience we define this struct to hold human readable form of UBE ciphertext material
typedef struct ct_header{
	char *OC0;
	char *OC1;
	char *C0;
	char *C1;
}* ct_text;


int aes_init(const char *keydata, int keydata_len, unsigned char *key, unsigned char *iv);

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

void shaCrypt(unsigned char *input, int length, const char *key, int keylen);

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length);

int Base64Encode(unsigned char* buffer, size_t length, char** b64text);

void Okeygen(unsigned char *pps, int num_users, char **public_keys, char **km, char**gamma);

//for convenience get in CT in readable form in CM and pass on to extension
void get_text_from_ct(ct CT, ct_text CM);

void get_ct_from_text(global_broadcast_params_t gbp, ct CT, const char* OC0, const char* OC1, const char* C0, const char* C1);

int encrypt_file(unsigned char *pps, char* gamma, int *shared_users, int num_users, unsigned char* plaintext, unsigned char* ciphertext, ct_text cm, char *t);

int decrypt_file(unsigned char *ciphertext, int cipherlen, unsigned char* pps, const char *OC0, const char* OC1, const char* C0, const char* C1, int user_id, int *shared_users, int recipients, const char *km, const char *rsa_privateKey,unsigned char* plaintext);

void share_file(unsigned char* pps, int *shared_users, int num_users, char *OC1, char *C1, char *t_str, char *t_str_new, char *new_OC1, char *new_C1);

void revokeUser(unsigned char* pps, ct_text CM,const char* t_str,const char* t_str_latest,const char *publicKey, int* revoke, int num_users, char **k1, char **k1_new, char* t_new_str);