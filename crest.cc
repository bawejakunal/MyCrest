// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/module.h"
#include "ppapi/cpp/var.h"
#include "ppapi/cpp/var_array_buffer.h"
#include "ppapi/cpp/var_dictionary.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <ctime>
#include <string>
#include "bgw.h"
extern "C" {
  #include "crest_main.h"
}

class CrestInstance : public pp::Instance {
 public:
  explicit CrestInstance(PP_Instance instance)
      : pp::Instance(instance) {}
  virtual ~CrestInstance() {}

  virtual void HandleMessage(const pp::Var& var_message) {
    // Ignore the message if it is not a string.
    if (!var_message.is_dictionary())
      return;

    pp::VarDictionary dict_message(var_message);
    pp::Var var_action = dict_message.Get("action");
    if (!var_action.is_string())
      return;
    std::string action = var_action.AsString();

    //check the action requested from browser in the if-else ladder and perform the action
    if(action == "osetup")
    {
      char *key = (char*)malloc(10);
      char **km, **public_keys;
      char *gamma;
      int i,num_users;

      pp::VarDictionary reply,key_material;
      std::string pkey;
      pp::Var ppsParams = dict_message.Get("ppsParams");
      pp::VarDictionary public_key_dict(dict_message.Get("public_keys")); //extract the json formatted public keys from this
      pp::VarArrayBuffer buffer(ppsParams);

      if (buffer.ByteLength() == 0)
        return;
      
      unsigned char* pps = static_cast<unsigned char*>(buffer.Map());
      memcpy(&num_users, pps, 4);

      public_keys = (char**)malloc(num_users*sizeof(char*));
      for(i=1;i<=num_users;i++)
      {
        sprintf(key, "%d", i);
        pkey = public_key_dict.Get(key).AsString();
        public_keys[i-1]=(char*)malloc(pkey.length()+1);
        sprintf(public_keys[i-1], "%s",pkey.c_str());
      }

      km = (char**)malloc(sizeof(char*)*num_users);
      Okeygen(pps,num_users,public_keys,km,&gamma);

      reply.Set("action","osetup");
      for(i=0;i<num_users;i++)
      {
        sprintf(key, "%d", i+1);
        key_material.Set(key,km[i]);
      }
      reply.Set("km",key_material);
      reply.Set("gamma",gamma);
      PostMessage(reply);

      //free the memory for all mallocs, even those done inside the function calls
      buffer.Unmap();
      free(gamma);
      free(key);
      for(i=0;i<num_users;i++)
      {
        free(km[i]);
        free(public_keys[i]);
      }
      free(public_keys);
      free(km);
    }
    else if(action == "encryption")
    {
      std::string content = dict_message.Get("content").AsString();
      pp::VarArrayBuffer pps_buffer(dict_message.Get("ppsParams"));
      pp::VarArray shared(dict_message.Get("shared_list"));
      std::string gamma = dict_message.Get("gamma").AsString();

      char *t = (char*)malloc(MAX_ELEMENT_LEN*sizeof(char));  //get t for file and store in database
      int i;
      int num_users=shared.GetLength();
      int *shared_users = (int*)malloc(num_users*sizeof(int));
      for (i = 0; i < num_users; ++i)
        shared_users[i]=shared.Get(i).AsInt();

      if (pps_buffer.ByteLength() == 0)
        return;
      unsigned char* pps = static_cast<unsigned char*>(pps_buffer.Map());
      // memcpy(&num_users, pps, 4);

      int len = content.length()+EVP_MAX_BLOCK_LENGTH + 1;
      unsigned char *ciphertext = (unsigned char*)malloc(len*sizeof(unsigned char));
      ct_text CM = (ct_text)malloc(sizeof(ct_header));

      len = encrypt_file(pps, (char*)gamma.c_str(), shared_users, num_users, (unsigned char*)(content.c_str()), ciphertext, CM, t);
      pps_buffer.Unmap();
      
      pp::VarArrayBuffer buffer(len);
      void* buffer_ptr = buffer.Map();
      memcpy(buffer_ptr, ciphertext, len);
      buffer.Unmap();
      //encryption ends here

      //prepare reply to be sent to browser for uploading
      pp::VarDictionary CT;
      pp::VarDictionary reply;
      reply.Set("action","encryption");
      reply.Set("ciphertext",buffer);
      reply.Set("fileSize",len);
      reply.Set("filePath", dict_message.Get("filePath").AsString());
      reply.Set("fileType", dict_message.Get("fileType").AsString());
      CT.Set("OC0",CM->OC0);
      CT.Set("OC1",CM->OC1);
      CT.Set("C0",CM->C0);
      CT.Set("C1",CM->C1);
      reply.Set("CT",CT);
      reply.Set("shared_users",shared);
      reply.Set("t",t);
      PostMessage(reply);
      
      //free all the memory allocated to data structures
      free(t);
      free(shared_users);
      free(ciphertext);
      free(CM->OC0);
      free(CM->OC1);
      free(CM->C0);
      free(CM->C1);
      free(CM);
    }
    else if(action == "decryption")
    {
      pp::VarDictionary reply;
      std::string OC0,OC1,C0,C1;
      pp::VarArrayBuffer buffer(dict_message.Get("content"));
      std::string rsa_key = dict_message.Get("secret_rsa").AsString();
      std::string km = dict_message.Get("km").AsString();
      pp::VarDictionary CT(dict_message.Get("CT"));
      pp::VarArrayBuffer pps_buffer(dict_message.Get("ppsParams"));
      int user_id = dict_message.Get("user_id").AsInt();
      OC0 = CT.Get("OC0").AsString();
      OC1 = CT.Get("OC1").AsString();
      C0 = CT.Get("C0").AsString();
      C1 = CT.Get("C1").AsString();
      pp::VarArray shared(dict_message.Get("shared_users"));
      int i, num_users = shared.GetLength();
      int *shared_users = (int*)malloc(num_users*sizeof(int));
      for (i = 0; i < num_users; ++i)
        shared_users[i] = shared.Get(i).AsInt();
     
      if (pps_buffer.ByteLength() == 0)
        return;
      unsigned char* pps = static_cast<unsigned char*>(pps_buffer.Map());

      int cipherlen = buffer.ByteLength();
      int len = cipherlen + EVP_MAX_BLOCK_LENGTH;
      unsigned char *plaintext = (unsigned char*)malloc(len*sizeof(unsigned char));
      unsigned char* ciphertext = static_cast<unsigned char*>(buffer.Map());

      len = decrypt_file(ciphertext,cipherlen,pps,OC0.c_str(),OC1.c_str(),C0.c_str(),C1.c_str(),user_id,shared_users,num_users,km.c_str(),rsa_key.c_str(),plaintext);
      pps_buffer.Unmap();
      buffer.Unmap();
      //aes decryption ends here

      reply.Set("action","decryption");
      reply.Set("plaintext", (char*)plaintext);
      PostMessage(reply);

      free(plaintext);
      free(shared_users);
    }
    else if(action == "share")
    {
      pp::VarDictionary metadata(dict_message.Get("metadata"));
      pp::VarArrayBuffer pps_buffer(dict_message.Get("ppsParams"));
      pp::VarDictionary reply;
      
      if (pps_buffer.ByteLength() == 0)
        return;
      unsigned char* pps = static_cast<unsigned char*>(pps_buffer.Map());
      
      std:: string OC1,C1,gamma,t,t_new;
      OC1 = metadata.Get("OC1").AsString();
      C1 = metadata.Get("C1").AsString();
      gamma = metadata.Get("gamma").AsString();
      t = metadata.Get("t").AsString();
      t_new = metadata.Get("t_new").AsString();
      
      pp::VarArray shared(metadata.Get("shared_users"));
      int i,num_users = shared.GetLength();
      int *shared_users = (int*)malloc(sizeof(int)*num_users);
      char *OC1_new = (char*)malloc(MAX_ELEMENT_LEN*sizeof(char));
      char *C1_new = (char*)malloc(MAX_ELEMENT_LEN*sizeof(char));

      for(i=0;i<num_users;i++)
        shared_users[i] = shared.Get(i).AsInt();
      
      share_file(pps, shared_users, num_users, (char*)OC1.c_str(), (char*)C1.c_str(), (char*)t.c_str(), (char*)t_new.c_str(), OC1_new, C1_new);

      reply.Set("action","share");
      reply.Set("OC1",OC1_new);
      reply.Set("C1",C1_new);
      reply.Set("shared_users",shared);
      reply.Set("File_id",metadata.Get("fileId").AsInt());
      reply.Set("shared_url",dict_message.Get("shared_url").AsString());
      PostMessage(reply);

      //free memory allocated
      free(OC1_new);
      free(C1_new);
      free(shared_users);
      pps_buffer.Unmap();
    }
    else if (action=="revoke")
    {
      pp::VarDictionary reply;
      std::string OC0,OC1,C0,C1,t,t_new,publicKey;
      OC0 = dict_message.Get("OC0").AsString();
      OC1 = dict_message.Get("OC1").AsString();
      C0 = dict_message.Get("C0").AsString();
      C1 = dict_message.Get("C1").AsString();
      t = dict_message.Get("t").AsString();
      t_new = dict_message.Get("t_new").AsString();
      publicKey = dict_message.Get("publicKey").AsString();
      pp::VarArrayBuffer pps_buffer(dict_message.Get("ppsParams"));
      if (pps_buffer.ByteLength() == 0)
        return;
      unsigned char* pps = static_cast<unsigned char*>(pps_buffer.Map());
      pp::VarArray revoke(dict_message.Get("revoke"));
      int i, num_users = revoke.GetLength();
      int *revoke_list = (int*)malloc(sizeof(int)*num_users);

      for (i = 0; i < num_users; ++i)
        revoke_list[i] = revoke.Get(i).AsInt();

      char *C0_new, *OC1_new, *C1_new,*t_str;
      char **k1,**k1_new;
      C0_new = (char*)malloc(MAX_ELEMENT_LEN*sizeof(char));
      C1_new = (char*)malloc(MAX_ELEMENT_LEN*sizeof(char));
      OC1_new = (char*)malloc(MAX_ELEMENT_LEN*sizeof(char));
      t_str = (char*)malloc(MAX_ELEMENT_LEN*sizeof(char));

      ct_text CM = (ct_text)malloc(sizeof(ct_header));
      CM->OC0=(char*)OC0.c_str();
      CM->OC1=(char*)OC1.c_str();
      CM->C0=(char*)C0.c_str();
      CM->C1=(char*)C1.c_str();

      k1 = (char**)malloc(sizeof(char*));
      k1_new = (char**)malloc(sizeof(char*));

      revokeUser(pps,CM,t.c_str(),t_new.c_str(),publicKey.c_str(),revoke_list,num_users,k1,k1_new,t_str);

      reply.Set("action","revoke");
      reply.Set("revoke",revoke);
      reply.Set("OC1",CM->OC1);
      reply.Set("C1",CM->C1);
      reply.Set("C0",CM->C0);
      reply.Set("k1",*k1);
      reply.Set("k1_new",*k1_new);
      reply.Set("t",t_str);
      reply.Set("filePath",dict_message.Get("filePath").AsString());

      PostMessage(reply);

      //free the memory
      pps_buffer.Unmap();
      free(*k1_new);
      free(k1_new);
      free(*k1);
      free(k1);
      free(C0_new);
      free(C1_new);
      free(OC1_new);
    }
  }
};

class CrestModule : public pp::Module {
 public:
  CrestModule() : pp::Module() {}
  virtual ~CrestModule() {}

  virtual pp::Instance* CreateInstance(PP_Instance instance) {
    return new CrestInstance(instance);
  }
};

namespace pp {

Module* CreateModule() {
  return new CrestModule();
}

}  // namespace pp
