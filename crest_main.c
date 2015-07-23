#include "crest_main.h"

int padding = RSA_PKCS1_PADDING;

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/*Initialise 256 bit key and IV for cipher. Returns 0 on success, 1 on failure*/
int aes_init(const char *keydata, int keydata_len, unsigned char *key, unsigned char *iv)
{
  const char *salt = "1234554321";

  if(!EVP_BytesToKey(EVP_aes_256_ctr(), EVP_sha1(), (unsigned char *)salt, (unsigned char *) keydata, keydata_len, 5, key, iv))
  {
      fprintf(stderr, "EVP_BytesToKey failed\n");
      return 1;
  }
  return 0;
}

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len = 0;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len += len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len = 0;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) 
    handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len += len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  plaintext[plaintext_len]='\0';
  return plaintext_len;
}

/* 
 * Since it is a one time padded XOR based encryption this function can be used to both encrypt and decrypt the data
 * Works in place on the input string
 */
void shaCrypt(unsigned char *input, int length, const char *key, int keylen)
{
  //size_t keylen = strlen(key);
  int i, j, numOfChunks = (int)ceil((float)length/20.0);  //20 bytes is the length of sha1 hash
  char *sha_in = (char*)malloc((keylen+2)*sizeof(char));
  unsigned char *sha_out = (unsigned char*)malloc(20*sizeof(unsigned char));
  char a[2];
  strncpy(sha_in,key,(size_t)keylen);
  sha_in[keylen]='\0';

  for (i = 0; i < numOfChunks; ++i)
  {
    snprintf(a,2,"%d",i);
    strcat(sha_in,a);

    SHA1((unsigned char*)sha_in, strlen(sha_in), sha_out);  //generate SHA1 hash after concatenating the key

    j=0;
    while(j<SHA_DIGEST_LENGTH && (SHA_DIGEST_LENGTH*i + j)<length)
    {
      input[SHA_DIGEST_LENGTH*i + j] = input[SHA_DIGEST_LENGTH*i + j]^sha_out[j];
      j++;
    }
    sha_in[strlen(sha_in)-1]='\0';
  }
  input[length]='\0';
  free(sha_in);
  free(sha_out);

  return;
}

//for convenience get in CT in readable form in CM and pass on to extension
void get_text_from_ct(ct CT, ct_text CM)
{
  CM->OC0 = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(CM->OC0, MAX_ELEMENT_LEN, CT->OC0);

  CM->OC1 = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(CM->OC1, MAX_ELEMENT_LEN, CT->OC1);

  CM->C0 = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(CM->C0, MAX_ELEMENT_LEN, CT->C0);

  CM->C1 = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(CM->C1, MAX_ELEMENT_LEN, CT->C1);

  return;
}

//get CT from CM
void get_ct_from_text(global_broadcast_params_t gbp, ct CT, const char* OC0, const char* OC1, const char* C0, const char* C1)
{
  element_init(CT->C0, gbp->pairing->G1);
  element_init(CT->C1, gbp->pairing->G1);
  element_init(CT->OC0, gbp->pairing->G1);
  element_init(CT->OC1, gbp->pairing->G1);

  element_set_str(CT->OC0, OC0, PBC_CONVERT_BASE);
  element_set_str(CT->OC1, OC1, PBC_CONVERT_BASE);
  element_set_str(CT->C0, C0, PBC_CONVERT_BASE);
  element_set_str(CT->C1, C1, PBC_CONVERT_BASE);

  return;
}

//encrypt the contents of file before uploading and set the CT header
//returns lenght of ciphertext
//malloc ciphertext, CM before using here
//replace num_users with set of users
int encrypt_file(unsigned char *pps, char* gamma, int *shared_users, int num_users, unsigned char* plaintext, unsigned char* ciphertext, ct_text CM, char *t)
{
  ct CT = (ct)pbc_malloc(sizeof(struct ciphertext_s));
  element_t EK;
  int len;
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

  char *ek = (char*)malloc(MAX_ELEMENT_LEN);  //extract ek
  unsigned char k0[SHA_DIGEST_LENGTH];
  unsigned char k1[SHA_DIGEST_LENGTH];

  //generate EK and CT
  EK_CT_generate(gamma, shared_users, num_users, pps, CT, EK, t);

  //extract EK in string
  element_snprint(ek,MAX_ELEMENT_LEN,EK);

  //calculate k0=H(EK||0)
  strcat(ek,"0");
  SHA1((unsigned char*)ek,strlen(ek),k0);

  //calculate k1=H(EK||1)
  ek[(int)strlen(ek)-1]='\0'; //remove concatenated 0 to substitute 1, in principal you can do away with this step as well
  strcat(ek,"1");
  SHA1((unsigned char*)ek,strlen(ek),k1);

  //inner layer AES encryption using k0
  aes_init((const char*)k0,SHA_DIGEST_LENGTH, key, iv);
  len = aes_encrypt(plaintext, (int)strlen((char*)plaintext), key, iv, ciphertext);

  //outer layer encryption SHA xor method using k1
  shaCrypt(ciphertext, len, (const char*)k1, SHA_DIGEST_LENGTH);

  //copy CT to human readable form in CM
  get_text_from_ct(CT,CM);

  //free memory
  pbc_free(CT);

  //return length of ciphertext
  return len;
}

//obtain innner and outer encryption keys
void get_key_from_ct(global_broadcast_params_t gbs, ct CT, element_t sk_i, int user_id, int* shared_users, int recipients, unsigned char* k0, unsigned char *k1)
{
  element_t EK0, EK1, num0, num1, denom0, denom1;
  int j;
  char *ek0 = (char*)malloc(MAX_ELEMENT_LEN);
  char *ek1 = (char*)malloc(MAX_ELEMENT_LEN);

  //Multiply sk_i as given in paper to get one part of denominator
  for(j=0;j<recipients;j++)
    if(shared_users[j] != user_id)
      element_mul(sk_i, sk_i, gbs->gs[(gbs->num_users)-shared_users[j]+user_id]);

  //obtain k0
  element_init(num0,gbs->pairing->GT);
  element_init(denom0,gbs->pairing->GT);
  element_init(EK0,gbs->pairing->GT);
  element_pairing(num0,gbs->gs[user_id-1],CT->OC1);
  element_pairing(denom0,sk_i,CT->OC0);
  element_div(EK0,num0,denom0);
  element_snprint(ek0,MAX_ELEMENT_LEN,EK0);
  strcat(ek0,"0");
  SHA1((unsigned char*)ek0,strlen(ek0),k0);

  //obtain k1
  element_init(num1,gbs->pairing->GT);
  element_init(denom1,gbs->pairing->GT);
  element_init(EK1,gbs->pairing->GT);
  element_pairing(num1,gbs->gs[user_id-1],CT->C1);
  element_pairing(denom1,sk_i,CT->C0);
  element_div(EK1,num1,denom1);
  element_snprint(ek1,MAX_ELEMENT_LEN,EK1);
  strcat(ek1,"1");
  SHA1((unsigned char*)ek1,strlen(ek1),k1);

  free(ek0);
  free(ek1);
  return;
}

//decrypt the contents of downloaded file
int decrypt_file(unsigned char *ciphertext, int cipherlen, unsigned char* pps, const char *OC0, const char* OC1, 
  const char* C0, const char* C1, int user_id, int *shared_users, int recipients, const char *km, const char *rsa_privateKey,unsigned char* plaintext)
{
  unsigned char *enc_sk,*sk;
  size_t enc_sk_len;
  int sk_len, len;
  global_broadcast_params_t gbs;
  element_t sk_i;
  ct CT = (ct)pbc_malloc(sizeof(struct ciphertext_s));
  unsigned char *k0 = (unsigned char*)malloc(SHA_DIGEST_LENGTH*sizeof(unsigned char*));
  unsigned char *k1 = (unsigned char*)malloc(SHA_DIGEST_LENGTH*sizeof(unsigned char*));
  unsigned char aes_key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

  //base64 decode to get the km encrypted under public key of user
  //stored in enc_sk
  Base64Decode((char*)km, &enc_sk, &enc_sk_len);  //base64decoding of km

  //decrypt enc_sk to sk
  sk = (unsigned char*)malloc(sizeof(unsigned char)*373); //3072 bits RSA encryption can give at max 373 bytes plaintext
  sk_len = private_decrypt(enc_sk,enc_sk_len,(unsigned char*)rsa_privateKey, sk);
  sk[sk_len]='\0';  //private decrypt doesn't appends with null char so we have to do that

  //some setup before extracting k0 and k1
  //done here instead of writing a separate function so as to save double work
  setup_global_broadcast_params(&gbs,pps);
  get_ct_from_text(gbs,CT,OC0,OC1,C0,C1);
  element_init_G1(sk_i, gbs->pairing);
  element_set_str(sk_i, (char*)sk, PBC_CONVERT_BASE);
  get_key_from_ct(gbs,CT,sk_i,user_id,shared_users,recipients,k0,k1);

  //outer layer decrypt
  shaCrypt(ciphertext, cipherlen, (const char*)k1, SHA_DIGEST_LENGTH);

  //inner layer decryption
  aes_init((const char*)k0, SHA_DIGEST_LENGTH, aes_key, iv);
  len = aes_decrypt(ciphertext, cipherlen, aes_key, iv, plaintext);

  //free some memory
  FreeCT(CT);
  free(k0);
  free(k1);
  return len;
}

//intialise RSA parameters for key generation
RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        fprintf(stdout, "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        fprintf(stdout, "Failed to create RSA\n");
    }
 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
  size_t len = strlen(b64input),
    padding = 0;
 
  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
 
  return (len*3)/4 - padding;
}
 
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
  BIO *bio, *b64;
 
  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
 
  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
 
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
  *length = BIO_read(bio, *buffer, strlen(b64message));
  assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong

  (*buffer)[decodeLen] = '\0';
  BIO_free_all(bio);
 
  return (0); //success
}

int Base64Encode(unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;
 
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
 
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);

  *b64text = (char*) malloc((bufferPtr->length + 1) * sizeof(char));
  memcpy(*b64text, bufferPtr->data, bufferPtr->length);
  (*b64text)[bufferPtr->length] = '\0';

  BIO_free_all(bio);
 
  return (0); //success
}

void Okeygen(unsigned char *pps, int num_users, char **public_keys, char **km, char **gamma)
{
  int i,len;
  global_broadcast_params_t gbs;
  char *sk = (char*)malloc(MAX_ELEMENT_LEN);
  char *temp = (char*) malloc(385*sizeof(char)); //we follow 384 bytes(3072 bits) RSA encryption + 1 for null char

  //Global Setup of gbs params
  setup_global_broadcast_params(&gbs, pps);

  //get randomly generated user gamma value
  *gamma = (char*)malloc(sizeof(char)*MAX_ELEMENT_LEN);
  element_snprint(*gamma,MAX_ELEMENT_LEN,gbs->gamma);  //get randomly picked gamma as a string

  if(num_users!=gbs->num_users)
  {
    fprintf(stderr, "PPS params inconsistent values\n");
    return;
  }

  //compute all the sk[i] that were not previously computed
  for (i = 0; i < gbs->num_users; i++)
  {
    element_pow_zn(gbs->gs[i], gbs->gs[i], gbs->gamma);   //gi^gamma as the sk[i]
    element_snprint(sk, MAX_ELEMENT_LEN, gbs->gs[i]);
    len = public_encrypt((unsigned char*)sk,(int)strlen(sk),(unsigned char*)public_keys[i], (unsigned char*)temp);
    Base64Encode((unsigned char*)temp, len, &km[i]);
  }
  free(temp);
  free(sk);
  return;
}

//Generate new values for OC1 and C1 for ciphertext update
void share_file(unsigned char* pps, int *shared_users, int num_users, char *OC1, char *C1, char *t_str, char *new_OC1, char *new_C1)
{
  int i;
  global_broadcast_params_t gbs;
  element_t OC1_new,C1_new,t;

  setup_global_broadcast_params(&gbs,pps);  //dont use gamma, its randomly generated and not user's unique value here

  element_init(OC1_new,gbs->pairing->G1);
  element_init(C1_new,gbs->pairing->G1);
  element_init_Zr(t, gbs->pairing);

  element_set_str(OC1_new,OC1,PBC_CONVERT_BASE);
  element_set_str(C1_new,C1,PBC_CONVERT_BASE);
  element_set_str(t,t_str,PBC_CONVERT_BASE);

  for(i=0;i<num_users;i++)
  {
    element_pow_zn(gbs->gs[(gbs->num_users)-shared_users[i]], gbs->gs[(gbs->num_users)-shared_users[i]], t);
    element_mul(OC1_new, OC1_new, gbs->gs[(gbs->num_users)-shared_users[i]]); //multiply to oc1
    element_mul(C1_new, C1_new, gbs->gs[(gbs->num_users)-shared_users[i]]); //multiply to c1
  }

  element_snprint(new_OC1,MAX_ELEMENT_LEN,OC1_new);
  element_snprint(new_C1,MAX_ELEMENT_LEN,C1_new);

  //free memeory
  element_clear(OC1_new);
  element_clear(C1_new);
  element_clear(t);

  return;
}

void revokeUser(unsigned char* pps, ct_text CM,const char* t_str,const char *publicKey, int* revoke, int num_users, char **k1, char **k1_new, char* t_new_str)
{
  
  element_t C0,OC1,C1,t,EK,t_new;
  global_broadcast_params_t gbs;
  char *ek1;
  int len,i;
  unsigned char *temp_k1 = (unsigned char*)malloc(SHA_DIGEST_LENGTH*sizeof(unsigned char*));
  unsigned char *temp_k1_new = (unsigned char*)malloc(SHA_DIGEST_LENGTH*sizeof(unsigned char*));
  unsigned char *temp = (unsigned char*)malloc(385*sizeof(unsigned char));

  setup_global_broadcast_params(&gbs,pps);

  element_init_Zr(t,gbs->pairing);
  element_set_str(t,t_str,PBC_CONVERT_BASE);

  element_init(EK, gbs->pairing->GT);
  element_pairing(EK, gbs->gs[0],gbs->gs[gbs->num_users-1]);
  element_pow_zn(EK,EK,t);  //recovered the latest EK
  
  //generate k1
  ek1 = (char*)malloc(MAX_ELEMENT_LEN);
  element_snprint(ek1,MAX_ELEMENT_LEN,EK);
  strcat(ek1,"1");
  SHA1((unsigned char*)ek1,strlen(ek1),temp_k1);
  len = public_encrypt(temp_k1,SHA_DIGEST_LENGTH,(unsigned char*)publicKey,temp);
  Base64Encode(temp, len, k1);
  free(temp_k1);

  element_init_Zr(t_new,gbs->pairing);
  element_random(t_new);
  element_snprint(t_new_str,MAX_ELEMENT_LEN,t_new);
  
  //generate k1'
  element_pow_zn(EK,EK,t_new);
  element_snprint(ek1,MAX_ELEMENT_LEN,EK);
  strcat(ek1,"1");
  SHA1((unsigned char*)ek1,strlen(ek1),temp_k1_new);
  len = public_encrypt(temp_k1_new,SHA_DIGEST_LENGTH,(unsigned char*)publicKey,temp);
  Base64Encode(temp, len, k1_new);
  free(ek1);
  free(temp);
  free(temp_k1_new);

  element_init(C0,gbs->pairing->G1);
  element_init(C1,gbs->pairing->G1);
  element_init(OC1,gbs->pairing->G1);
  element_set_str(C0,CM->C0,PBC_CONVERT_BASE);
  element_set_str(C1,CM->C1,PBC_CONVERT_BASE);
  element_set_str(OC1,CM->OC1,PBC_CONVERT_BASE);

  //C0 = (C0)^t'
  element_pow_zn(C0,C0,t_new);
  element_snprint(CM->C0,MAX_ELEMENT_LEN,C0);

  //OC1'
  for(i=0;i<num_users;i++)
  {
    element_pow_zn(gbs->gs[(gbs->num_users)-revoke[i]],gbs->gs[(gbs->num_users)-revoke[i]],t);
    element_div(OC1,OC1,gbs->gs[(gbs->num_users)-revoke[i]]);
  }
  element_snprint(CM->OC1,MAX_ELEMENT_LEN,OC1);

  //C1'=(OC1)^t'
  element_pow_zn(C1,OC1,t_new);
  element_snprint(CM->C1,MAX_ELEMENT_LEN,C1);

  element_clear(C0);
  element_clear(C1);
  element_clear(OC1);
  element_clear(t);
  element_clear(t_new);
  element_clear(EK);

  return;
}