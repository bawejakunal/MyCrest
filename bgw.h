#ifndef PBC_BCE_H_
#define PBC_BCE_H_

#include <string.h>
#include "pbc/pbc.h"


/* **********************************************************
   DEBUG having the debug flag turned on spews out lots of
   debugging output.
*********************************************************  */
#define DEBUG 0

/* **********************************************************
  PBC_PAIRING_PARAMS stores the content of pairing parameters,
  including all the types, etc..
  *********************************************************  */

#define MAX_ELEMENT_LEN 1000
#define MPZ_CONVERT_BASE 62
#define PBC_CONVERT_BASE 10

#define PBC_PAIRING_PARAMS "type a\n \
  q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n \
  h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n \
  r 730750818665451621361119245571504901405976559617\n \
  exp2 159\n \
  exp1 107\n \
  sign1 1\n \
  sign0 1\n"
/*
PRIVATE GAMMA
*/
#define PRIVATE_GAMMA "514443474460839782450589865266227244330811833490"


/* **********************************************************
   GLOBAL BROADCAST PARAMS--
   Stores the:
   curve info--PUBLIC
   group elements--PUBLIC
   num-users-PUBLIC
*********************************************************  */
typedef struct global_broadcast_params_s {
  pairing_t pairing;
  element_t g;
  element_t *gs;
  element_t gamma;
  int num_users;
}* global_broadcast_params_t;

/* **********************************************************
   CIPHERTEXT STRUCT
   Contains C0,C1,C0' and C1'
*********************************************************  */
typedef struct ciphertext_s {
  element_t OC0;
  element_t OC1;
  element_t C0;
  element_t C1;
}* ct;

/* **********************************************************
   These functions free the memory associated with various
   structures.  Note that the pointer you pass in will not
   be freed--you must free it manually to prevent freeing
   stack memory.
********************************************************** */

void FreeCT(ct CT);
void FreeGBP(global_broadcast_params_t gbp);


/* **********************************************************
   Extension sends the pps_compressed.txt contents here.
   The contents are the public parameter set PPs as described
   in the CREST paper.
*********************************************************  */
void setup_global_broadcast_params(global_broadcast_params_t *gbp,unsigned char* gbs_header);


/* **********************************************************
   This function generates encapsulation key EK and broadcast
   encryption ciphertext headr CT.
*********************************************************  */
void EK_CT_generate(char* gamma, int *shared_users, int num_users, unsigned char *pps, ct CT, element_t EK, char *t_str);

#endif