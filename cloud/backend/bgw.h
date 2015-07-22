/* Implementation of Boneh-Gentry-Waters broadcast encryption scheme
   Code by:  Matt Steiner   MattS@cs.stanford.edu

   Some changes by Ben Lynn blynn@cs.stanford.edu

   bce.h
*/

#include <string.h>
#include "pbc.h"


/* **********************************************************
   DEBUG having the debug flag turned on spews out lots of
   debugging output.
*********************************************************  */
#define DEBUG 0

#define MAX_ELEMENT_LEN 1000
#define MPZ_CONVERT_BASE 62
#define PBC_CONVERT_BASE 10
#define PUBLIC_G "[7998725336653383203658644639673805448553730986337128386926545744008381384348409264866333582258561179132241508936069720871865895053632019929236743348039021, 1993938860438750843589842757968313427718259534664174282914852335272086243792497573680387148722647412680490224484736059954284097163105446004304579443902885]"
#define PRIVATE_ALPHA "327381951474812263560188258339840236298386504075"  //this is supposed to be chosen randomly from Zp

/* **********************************************************
  PBC_PAIRING_PARAMS stores the content of pairing parameters,
  including all the types, etc..
  *********************************************************  */

#define PBC_PAIRING_PARAMS "type a\n \
  q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n \
  h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n \
  r 730750818665451621361119245571504901405976559617\n \
  exp2 159\n \
  exp1 107\n \
  sign1 1\n \
  sign0 1\n"

#define PBC_PAIRING_PARAMS2 "type a1\n \
p 48512875896303752499712277254589628516419352188294521198189567511009073158115045361294839347099315898960045398524682007334164928531594799149100548036445760110913157420655690361891290858441360807158247259460501343449199712532828063940008683740048500980441989713739689655610578458388126934242630557397618776539259\n\
n 36203638728584889925158415861634051131656232976339194924022065306723188923966451762160327870969638730567198058600508960697138006366861790409776528385407283664860565239295291314844246909284597617282274074224254733917313218308080644731349763985110821627195514711746037056425804819692632040479575042834043863089\n\
l 1340\n"
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
  element_t alpha;
  element_t *gs;
  int num_users;
}* global_broadcast_params_t;


/* **********************************************************
   These functions free the memory associated with various 
   structures.  Note that the pointer you pass in will not
   be freed--you must free it manually to prevent freeing
   stack memory.
********************************************************** */

void FreeGBP(global_broadcast_params_t gbp);


/* **********************************************************
   Sets up a global broadcast system by generating all of
   the gs, the hs, and their inverses.  Chooses random alpha
   for the exponent.  num_users must be a multiple of 8.
*********************************************************  */
void setup_global_broadcast_params(global_broadcast_params_t *gbp, 
				   int num_users);

void restore_global_broadcast_params(global_broadcast_params_t *gbp);


void update_after_revocation(const char* file_id);