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
#include <openssl/sha.h>
#include "bgw.h"

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

void log_pbc_element(element_t e, char* message){
  char* s = (char*) malloc(MAX_ELEMENT_LEN);
  int t;
  t = element_snprint(s, MAX_ELEMENT_LEN, e);
  printf( " message: %s, Log: %s\n", message, s);
  free(s);
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

void restore_global_broadcast_params2(global_broadcast_params_t *sys){
  unsigned char * buffer = 0;
  long length;
  FILE * f = fopen ("/tmp/gbs.txt", "rb");

  if (f){
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = (unsigned char*) malloc (length+1);
    if (buffer)
    {
      fread (buffer, 1, length, f);
    }
    fclose (f);
  }

  if (buffer){
    unsigned char* gbs_header = buffer;
    global_broadcast_params_t gbs;
    gbs = pbc_malloc(sizeof(struct global_broadcast_params_s));
     // Setup curve in gbp
    size_t count = strlen(PBC_PAIRING_PARAMS);
    if (pairing_init_set_buf(gbs->pairing, PBC_PAIRING_PARAMS, count)) pbc_die("pairing init failed");


    int num_users;
    memcpy(&num_users, gbs_header, 4);
    printf( "N = %d\n", num_users);
    gbs->num_users = num_users;
    gbs_header= gbs_header+4;
    printf( "Done reading N \n");
    element_t *lgs;
    int i;
    lgs = pbc_malloc(2 * num_users * sizeof(element_t));

    //generate g
    element_init(gbs->g, gbs->pairing->G1);
    gbs_header += in(gbs->g, gbs_header);
    printf( "Done reading G \n");
    log_pbc_element(gbs->g, "PUBLIC G");

    //Fill in the gs array
    for(i = 0; i < 2*num_users; i++) {
      element_init(lgs[i], gbs->pairing->G1);
      if(i == num_users)
        continue;
      gbs_header += in(lgs[i], gbs_header);
    }
    printf("Done getting lgs\n");
    //For simplicity & so code was easy to read
    gbs->gs = lgs;
    *sys = gbs;
   }
}

void restore_global_broadcast_params(global_broadcast_params_t *sys)
{
  global_broadcast_params_t gbs;

  gbs = pbc_malloc(sizeof(struct global_broadcast_params_s));

  // Setup curve G in gbs
  size_t count = strlen(PBC_PAIRING_PARAMS);
  if (!count) pbc_die("input error");
  if (pairing_init_set_buf(gbs->pairing, PBC_PAIRING_PARAMS, count))
    pbc_die("pairing init failed");

  FILE* file;
  file = fopen("/tmp/gbs.txt" , "r");
  char* line;
  size_t len=0;
  ssize_t read;
  int t, i=0, num_users;
  element_t *lgs;

  element_init_Zr(gbs->alpha, gbs->pairing);
  t=element_set_str(gbs->alpha, PRIVATE_ALPHA, PBC_CONVERT_BASE);

  while ((read = getline(&line, &len, file)) != -1) {
    char* tmp=strdup(line);
    strtok(tmp, "\n");
    if (i==0){
      num_users = atoi(tmp);
      gbs->num_users = num_users;
      lgs = pbc_malloc(2 * num_users * sizeof(element_t));
      if(!(lgs)) {
        printf("\nMalloc Failed\n");
        printf("Didn't finish system setup\n\n");
      }
    }
    else if (i == 1){
       //Set G as a chosen public value
      element_init(gbs->g, gbs->pairing->G1);
      t=element_set_str(gbs->g, tmp, PBC_CONVERT_BASE);
    }

    else{
      if (i-2 == num_users)
        i++;
      element_init(lgs[i-2], gbs->pairing->G1);
      t=element_set_str(lgs[i-2], tmp, PBC_CONVERT_BASE);
    }
    i++;
    free(tmp);
  }
  fclose(file);

  //For simplicity & so code was easy to read
  gbs->gs = lgs;
  *sys = gbs;
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

void update_after_revocation(const char* file_id){
  //read previous and current k1
  FILE* file = fopen("/tmp/k.txt" , "r");
  size_t len=0, clen;
  ssize_t read;
  char *old_k1, *new_k1;
  char* line;
  read = getline(&line, &len, file);
  old_k1 = strdup(line);
  read = getline(&line, &len, file);
  new_k1 = strdup(line);
  fclose(file);
  strtok(old_k1, "\n");
  strtok(new_k1, "\n");

  printf("old_k1 %s\n", old_k1);
  printf("new_k1 %s\n", new_k1);

  // read the ciphertext
  char* filename = (char*) malloc (100);
  strcpy(filename, "/tmp/");
  strcat(filename, file_id);
  unsigned char* aes_cipher;
  FILE * f = fopen (filename, "rb");
  if (f){
    fseek (f, 0, SEEK_END);
    clen = ftell (f);
    fseek (f, 0, SEEK_SET);
    aes_cipher = (unsigned char*) malloc (clen);
    if (aes_cipher)
    {
      fread (aes_cipher, 1, clen, f);
    }
    fclose (f);
  }

  //now xor with each block...
  int ilen=0;
  unsigned char* k1hash;
  unsigned char* k2hash;
  size_t length=base64Decode(old_k1, &k1hash);
  size_t length2=base64Decode(new_k1, &k2hash);

  for (ilen = 0; ilen < clen; ilen++)
    printf("%d-", aes_cipher[ilen]);
  printf("\n");

  unsigned char k_hash[SHA_DIGEST_LENGTH+1];
  unsigned char kp_hash[SHA_DIGEST_LENGTH+1];
  ilen=0;
  while (ilen < clen){
    int working_size = SHA_DIGEST_LENGTH;
    if (ilen + SHA_DIGEST_LENGTH > clen)
      working_size = clen - ilen;
    memcpy(k_hash, k1hash, SHA_DIGEST_LENGTH);
    memcpy(kp_hash, k2hash, SHA_DIGEST_LENGTH);
    k_hash[SHA_DIGEST_LENGTH] = '1';
    kp_hash[SHA_DIGEST_LENGTH] = '1';
    length = sizeof(k_hash);
    SHA1(k_hash, length, k1hash);
    SHA1(kp_hash, length, k2hash);
    int j;
    for (j=0; j < working_size; j++){
      aes_cipher[ilen+j] ^= k1hash[j];
      aes_cipher[ilen+j] ^= k2hash[j];
    }
    ilen += SHA_DIGEST_LENGTH;
  }

  for (ilen = 0; ilen < clen; ilen++)
    printf("%d-", aes_cipher[ilen]);
  printf("\n");

  f=fopen(filename, "wb");
  fwrite(aes_cipher, 1, clen, f);
  fclose(f);
}