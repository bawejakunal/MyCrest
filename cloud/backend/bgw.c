/* Implementation of Boneh-Gentry-Waters broadcast encryption scheme
 * Code by:  Matt Steiner   MattS@cs.stanford.edu
 *
 * Some changes by Ben Lynn blynn@cs.stanford.edu
 *
 * bce.c
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "bgw.h"

int padding = RSA_PKCS1_PADDING;

void FreeGBP(global_broadcast_params_t gbp)
{
  if(!gbp) {
    printf("error: null pointer passed to freeGBP\n");
    return;
  }
  //do something about the pairing
  element_clear(gbp->alpha);
  element_clear(gbp->g);
  int i;
  for(i = 0; i < 2*gbp->num_users; i++) {
    if(i == gbp->num_users)
      continue;
    element_clear(gbp->gs[i]);
  }
  pbc_free(gbp->gs);
  return;
}


void setup_global_broadcast_params(global_broadcast_params_t *sys, int num_users)
{
  global_broadcast_params_t gbs;

  gbs = pbc_malloc(sizeof(struct global_broadcast_params_s));

  // Setup curve in gbp
  size_t count = strlen(PBC_PAIRING_PARAMS);
  if (!count) pbc_die("input error");
  if (pairing_init_set_buf(gbs->pairing, PBC_PAIRING_PARAMS, count))
    pbc_die("pairing init failed");

  gbs->num_users = num_users;
  element_t *lgs;
  int i;

  lgs = pbc_malloc(2 * num_users * sizeof(element_t));
  if(!(lgs)) {
    printf("\nMalloc Failed\n");
    printf("Didn't finish system setup\n\n");
  }
  //Set g as a chosen public value
  element_init(gbs->g, gbs->pairing->G1);
  i=element_set_str(gbs->g, PUBLIC_G, PBC_CONVERT_BASE);

  //Get alpha from Zp as mentioned in the paper
  element_init_Zr(gbs->alpha, gbs->pairing);
  element_random(gbs->alpha);   //pick random alpha value and later delete from memory
  //i=element_set_str(gbs->alpha, PRIVATE_ALPHA, PBC_CONVERT_BASE); //alpha is initialised as secret and later removed from memory

  //Make the 0th element equal to g^alpha
  element_init(lgs[0], gbs->pairing->G1);
  element_pow_zn(lgs[0],gbs->g, gbs->alpha);

  //Fill in the gs and the hs arrays
  for(i = 1; i < 2*num_users; i++) {
    //raise alpha to one more power
    element_init(lgs[i], gbs->pairing->G1);
    element_pow_zn(lgs[i], lgs[i-1], gbs->alpha);
  }
  element_clear(lgs[num_users]);  //remove g^(alpha^(n+1)) as it can leak info about parameters

  //For simplicity & so code was easy to read
  gbs->gs = lgs;
  *sys = gbs;
}

static inline int in(element_t elem, unsigned char *my_feed) {
  int sz;
  printf( "Prepare reading sz\n");
  memcpy(&sz, my_feed, 4);
  printf( "Size of pbc element: %d\n", sz);
  unsigned char* data = pbc_malloc(sz);
  memcpy(data, my_feed+4, sz);
  element_from_bytes(elem, data);
  pbc_free(data);
  return sz+4;
}

//write bytes stream of element_t to a file
static inline void out(element_t elem, FILE *myfile)
{
  int sz = element_length_in_bytes_compressed(elem);
  fwrite(&sz, 4, 1, myfile);
  unsigned char* data = pbc_malloc(sz);
  if(!data) 
    printf("DATA IS NULL\n");
  element_to_bytes_compressed(data, elem);
  fwrite(data, sz, 1, myfile);
  pbc_free(data);
}

//store global parameters PPs in a file
void store_gbp_params(char *system_file,
     global_broadcast_params_t gbp)
{
  if(!gbp) {
    printf("ACK!  You gave me no broadcast params!  I die.\n");
    return;
  }
  if(!system_file){
    printf("ACK!  You gave me no system filename!  I die.\n");
    return;
  }

  FILE *f = fopen(system_file, "w");
  if(!f) {
    printf("ACK! couldn't write to file system.  I die\n");
    return;
  }

  //store num_users
  fwrite(&(gbp->num_users),4,1, f);

  //store g
  out(gbp->g, f);
  //if(DEBUG) printf("done storing g\n");

  //store gs
  int i;
  for(i = 0; i < 2*gbp->num_users; i++) {
    if(i == gbp->num_users)
      continue;
    out(gbp->gs[i], f);
    //if(DEBUG) printf("done storing g %d\n",i);
  }
  fclose(f);
  return;
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

/* open file and re-encrypt outer layer*/
int update_encryption(char *fileName, char *base_k1, char *base_k1_new, const char* privateKey)
{
  FILE *file;
  size_t cipherlen,keylen;
  unsigned char *ciphertext,*k1_temp,*k1_new_temp,*k1,*k1_new;

  printf("%s\n", privateKey);

  //read ciphertext from the file to be updated
  file = fopen(fileName,"rb");  //open in read binary stream mode
  if (file)
  {
    fseek (file, 0, SEEK_END);
    cipherlen = ftell (file);
    fseek (file, 0, SEEK_SET);
    ciphertext = (unsigned char*) malloc(cipherlen*sizeof(unsigned char));
    if (ciphertext)
    {
      fread (ciphertext, sizeof(unsigned char), cipherlen, file);
    }
    fclose (file);
  }

  //decrypt the data
  if(!Base64Decode(base_k1, &k1_temp, &keylen))
  {
    k1 = (unsigned char*)malloc(sizeof(unsigned char)*374);
    keylen = private_decrypt(k1_temp,keylen,(unsigned char *)privateKey, k1);
    k1[keylen]='\0';
    shaCrypt(ciphertext,(int)cipherlen, (const char *)k1, SHA_DIGEST_LENGTH);
    free(k1_temp);
    free(k1);
  }
  else
    return 1;

  //re-encrypt the data
  if(!Base64Decode(base_k1_new,&k1_new_temp,&keylen))
  {
    k1_new = (unsigned char*)malloc(sizeof(unsigned char)*374);
    keylen = private_decrypt(k1_temp,keylen,(unsigned char *)privateKey, k1_new);
    k1_new[keylen]='\0';
    shaCrypt(ciphertext,(int)cipherlen,(const char*)k1_new, SHA_DIGEST_LENGTH);
    free(k1_new_temp);
    free(k1_new);
  }
  else
    return 1;

  //write the encrypted data to file
  file = fopen(fileName,"wb");
  if (file)
  {
    fwrite(ciphertext, sizeof(unsigned char), cipherlen, file);
    fclose(file);
  }
  else
    return 1;

  file = fopen("yolo.txt","w");
  fprintf(file, "HELLO WORLD\n");
  fclose(file);

  //free memory for ciphertext
  free(ciphertext);
  return 0;
}