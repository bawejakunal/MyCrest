#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "bgw.h"

void FreeCT(ct CT)
{
  if(!CT) {
    printf("error: null pointer passed to freeCT\n");
    return;
  }
  element_clear(CT->OC0);
  element_clear(CT->OC1);
  element_clear(CT->C0);
  element_clear(CT->C1);
  pbc_free(CT);
  return;
}

void FreeGBP(global_broadcast_params_t gbp)
{
  int i;

  if(!gbp) {
    printf("error: null pointer passed to freeGBP\n");
    return;
  }
  
  //do something about the pairing
  element_clear(gbp->g);
  element_clear(gbp->gamma);
  
  for(i = 0; i < gbp->num_users; i++)
    element_clear(gbp->gs[i]);
  
  pbc_free(gbp->gs);
  pbc_free(gbp);
  return;
}


// void FreeBCS(broadcast_system_t bcs)
// {
//   if(!bcs) {
//     printf("error: null pointer passed to freeBCS\n");
//     return;
//   }
//   element_clear(bcs->encr_prod);
//   element_clear(bcs->pub_key);
//   element_clear(bcs->priv_key);
//   return;
// }

// void FreePK(priv_key_t key)
// {
//   if(!key) {
//     printf("error: null pointer passed to freePK\n");
//     return;
//   }
//   element_clear(key->g_i_gamma);
//   element_clear(key->g_i);
//   element_clear(key->decr_prod);
//   return;
// }


// static inline void out(element_t elem, FILE *myfile)
// {
//   int sz = element_length_in_bytes(elem);
//   fwrite(&sz, 4, 1, myfile);
//   unsigned char* data = pbc_malloc(sz);
//   if(!data) printf("DATA IS NULL\n");
//   element_to_bytes(data, elem);
//   fwrite(data, sz, 1, myfile);
//   pbc_free(data);
// }

static inline int in(element_t elem, unsigned char *my_feed) {
  int sz;
  // fprintf(stderr, "Prepare reading sz\n");
  memcpy(&sz, my_feed, 4);
  // fprintf(stderr, "Size of pbc element: %d\n", sz);
  unsigned char* data = pbc_malloc(sz);
  memcpy(data, my_feed+4, sz);
  element_from_bytes_compressed(elem, data);
  pbc_free(data);
  return sz+4;
}

//This function sets the global broadcast parameters downloaded as a file from the server
//Sets up the gamma value, dont forget to randomize gamma and store locally later please
void setup_global_broadcast_params(global_broadcast_params_t *sys,
           unsigned char* gbs_header)
{
  global_broadcast_params_t gbs;
  gbs = pbc_malloc(sizeof(struct global_broadcast_params_s));
   // Setup curve in gbp
  size_t count = strlen(PBC_PAIRING_PARAMS);
  if (pairing_init_set_buf(gbs->pairing, PBC_PAIRING_PARAMS, count))
    pbc_die("pairing init failed");

  int num_users;
  memcpy(&num_users, gbs_header, 4);
  
  gbs->num_users = num_users;
  gbs_header= gbs_header+4;
  
  element_t *lgs;
  int i;
  lgs = pbc_malloc(2 * num_users * sizeof(element_t));

  //generate g from the file contents
  element_init(gbs->g, gbs->pairing->G1);
  gbs_header += in(gbs->g, gbs_header);

  //Fill in the gi values in lgs[]
  for(i = 0; i < 2*num_users; i++) {
    element_init(lgs[i], gbs->pairing->G1);
    if(i == num_users)
      continue;
    gbs_header += in(lgs[i], gbs_header);
  }

  element_init_Zr(gbs->gamma, gbs->pairing);  //initialise gamma
  element_random(gbs->gamma); //pick random value of gamma
  //i=element_set_str(gbs->gamma, PRIVATE_GAMMA, PBC_CONVERT_BASE); //set a randomly picked gamma

  //For simplicity & so code was easy to read
  gbs->gs = lgs;
  *sys = gbs;
}

//Called in file encryption function to generate C0,C1,C0',C1' and EK
//returns CT,EK
void EK_CT_generate(char *gamma, int *shared_users, int num_users, unsigned char *pps, ct CT, element_t EK, char *t_str)
{

  global_broadcast_params_t gbs;
  element_t t;
  int j;

  //Global Setup of gbs params
  setup_global_broadcast_params(&gbs, pps);
  element_set_str(gbs->gamma, gamma, PBC_CONVERT_BASE); //it is important to set user gamma here else a random value will be used

  //pick a random value of t from Zr
  element_init_Zr(t, gbs->pairing);
  element_random(t);
  element_snprint(t_str,MAX_ELEMENT_LEN,t);

  //compute C0=g^t
  element_init(CT->OC0, gbs->pairing->G1);
  element_pow_zn(CT->OC0, gbs->g, t);

  //compute C1=(g^gamma)x(g[num_users+1-j]) for j in all shared users
  element_init(CT->OC1, gbs->pairing->G1);
  element_pow_zn(CT->OC1, gbs->g, gbs->gamma); //at this step C1 = g^gamma = v as given in paper
  for(j=0;j<num_users;j++)
    element_mul(CT->OC1, CT->OC1, gbs->gs[(gbs->num_users)-shared_users[j]]);
  element_pow_zn(CT->OC1, CT->OC1, t);

  //Duplicate C0'=C0
  element_init(CT->C0, gbs->pairing->G1);
  element_set(CT->C0,CT->OC0);

  //Duplicate C1'=C1
  element_init(CT->C1, gbs->pairing->G1);
  element_set(CT->C1,CT->OC1);

  //COMPUTE EK = e(g[n], g[1])^(t)
  element_init(EK, gbs->pairing->GT);
  element_pairing(EK, gbs->gs[0],gbs->gs[gbs->num_users-1]);  //at this step EK = e(g[1],g[n])
  element_pow_zn(EK,EK,t);  //EK = e(g[1],g[n])^t

  //free the memory for global broadcast params
  element_clear(t);
  FreeGBP(gbs);

  return;
}

