#include <string.h>
#include "bgw.h"

int main(int argc, char const *argv[])
{
  int ret;
  if (argc > 1)
  {
    if (argc == 3 && !strcmp(argv[1], "setup")){ 
      global_broadcast_params_t gbs;
      //Global Setup
      int n = atoi(argv[2]);      
      setup_global_broadcast_params(&gbs, n);
      
      FILE * file;
      file = fopen("pps.txt" , "w");
      int i = 0, t;

      //print number of users
      fprintf(file, "%d\n", n);  
      //print g to the file as first element of public parameter set PPs
      element_fprintf(file,"%B\n",gbs->g);
      
      //print gs[i] 2*n-1 times
      for (i=0; i < 2*n; i++){
        if (i==n)   //this was cleared in setup_global_broadcast_params
          continue;
        element_fprintf(file,"%B\n",gbs->gs[i]);
      }
      fclose(file);
      store_gbp_params("pps_compress.txt", gbs); //chekc bgw.c for explanation
      FreeGBP(gbs); //removing alpha and associated parameters from memory
      return 0;
    }
    else if (argc == 6 && !strcmp(argv[1], "revoke"))
    {
      ret = update_encryption((char*)argv[2],(char*)argv[3],(char*)argv[4],argv[5]);
      return ret;
    }
  }
  fprintf(stderr, "Run with ./mainbgw [task] [Other parameter]\n");
  fprintf(stderr, "For example ./mainbgw setup 16\n");

  return 1;
}