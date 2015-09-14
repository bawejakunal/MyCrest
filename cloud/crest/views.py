import json
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import requests
from .models import *
from django.core.servers.basehttp import FileWrapper
import subprocess
from Crypto.PublicKey import RSA
from Crypto import Random
import os
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND  = PROJECT_ROOT+"/backend/"
NUM_USERS = 100

def index(request):
    return HttpResponse("CREST Top Dir: " + PROJECT_ROOT)

#This is the setup process to generate all gi component. Run it once and only, otherwise it will
#invade the whole system. This stores the public parameter, private key, public key of user in database. 
def server_setup(request):
    try:
        process = subprocess.check_output(BACKEND+"mainbgw setup " + str(NUM_USERS), shell=True,\
                                          stderr=subprocess.STDOUT)

        for i in xrange(1,NUM_USERS+1):
            private = RSA.generate(3072,Random.new().read)
            public = private.publickey()
            new_user = User(public_rsa=public.exportKey(), secret_rsa=private.exportKey())
            new_user.save()

        # open_file.close()
        return HttpResponse("Done setting up...")

    except Exception as e:
        print "Error on setup" + str(e)
        raise e

#checks if user email id exists in database, if not then it adds it to the database
@csrf_exempt
def check_add_user(request):
    data = request.body
    ret_data={}
    user = User.objects.filter(email=data)    #search for users with email as sent by user
    if user:
        ret_data = {
            'success':True,
            'exist':True,
            'user_id':user[0].id
        }
    else:
        user_list = User.objects.filter(email="")
        user = list(user_list[:1])
        if user:
            user[0].email=data
            user[0].save()
            ret_data={
                'success':True,
                'exist':False,
                'user_id':user[0].id
            }
        else:
            ret_data={
                'success':False,
                'exist':False,
                'description':'Failed to find and add user\n'
            }
    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')


# This downloads the file with global parameters from the server, called by the JS in chrome extension
def get_pps_params(request):
    wrapper = FileWrapper(file("pps_compress.txt"))
    response = HttpResponse(wrapper, content_type='application/zip')
    response['Content-Disposition'] = 'attachment; filename=pps_compress.txt'
    return response


#This is called in extension JS to get the RSA public key list of users
#for whom the UBE scheme components have not yet been issued
#This can be further improvised by sending rsa keys for only those users for
#whom KM[i] values have not been specified in Recipient table
@csrf_exempt
def get_rsa_public_keys(request):
    try:
        return_data = {'success': True}
        for id in xrange(1,NUM_USERS+1):
            try:
                recipient = User.objects.get(id=id)
                return_data[id] = recipient.public_rsa
            except Exception as e:
                raise e
    except Exception as e:
        print "Errors " + str(e)
        return_data={
            'success': False,
            'error': str(e)
        }
    rdata = json.dumps(return_data)
    return HttpResponse(rdata, content_type='application/json')


#Add user generated secret keys km[i] to the database
@csrf_exempt
def add_ube_keys(request):
    data = json.loads(request.body)
    user_id  = data['user_id']
    return_data = {
        'success':True,
        'description':'UBE keys added successfully'
    }

    try:
        owner = User.objects.get(id=user_id)
        for i in data['keys']:
            try:
                i = long(i)
                recipient = User.objects.get(id=i)
                recipient = Recipient(owner_id=owner.id,receiver_id=recipient.id,km=data['keys'][str(i)])
                recipient.save()
            except Exception as e:
                    print 'Recipient not found'
                    raise e
        owner.gamma = data['gamma']
        owner.save()
    except Exception as e:
        print 'Owner not found or database inconsistent'
        raise e

    rdata = json.dumps(return_data)
    return HttpResponse(rdata, content_type='application/json')

#Upload file parameters to cloud server
@csrf_exempt
def upload_file_meta(request):
    data = json.loads(request.body)
    file_meta = FileDB(filePath=data['filePath'],owner_id=data['owner'],OC0=data['CT']['OC0'],OC1=data['CT']['OC1'],C1=data['CT']['C1'],C0=data['CT']['C0'],t=data['t'],t_new=data['t'],shared_url=data['shared_url'])
    file_meta.save()

    FileShare(File_id=file_meta.id,owner_id=data['owner'],receiver_id=data['owner']).save()  #add owner once and only once in shared table
    for receiver in data['shared']:
        if receiver != data['owner']:   #this is to prevent duplicate entries of owner in shared user table
            FileShare(File_id=file_meta.id,owner_id=data['owner'],receiver_id=receiver).save()

    return_data ={
        'success':True,
    }

    ret_data = json.dumps(return_data)
    return HttpResponse(ret_data, content_type='application/json')

#Download file metadata for downloading
@csrf_exempt
def download_file_meta(request):
    data = json.loads(request.body)
    id_list = []
    try:
        if 'owner' in data:
            File = FileDB.objects.get(filePath=data['filePath'],owner_id=data['owner'])
            user = User.objects.get(id=data['owner'])
            recipient = Recipient.objects.get(owner_id=data['owner'],receiver_id=data['owner'])
        elif 'receiver' in data:
            File = FileDB.objects.get(shared_url=data['shared_url'])
            user = User.objects.get(id=data['receiver'])
            recipient = Recipient.objects.get(owner_id=File.owner_id,receiver_id=data['receiver'])
        file_share = FileShare.objects.filter(File_id=File.id)
        for i in file_share:
            id_list.append(i.receiver_id)

        return_data = {
            'success':True,
            'CT':{
                'OC0': File.OC0,
                'OC1': File.OC1,
                'C0': File.C0,
                'C1': File.C1
            },
            'secret_rsa':user.secret_rsa,
            'km': recipient.km,
            'shared_users':id_list
        }
    except Exception as e:
        print e
        return_data={
            'success': False,
            'error':str(e)
        }

    rdata = json.dumps(return_data)
    return HttpResponse(rdata, content_type='application/json')

@csrf_exempt
def delete_file_meta(request):
    data = json.loads(request.body)
    try:
        File = FileDB.objects.get(filePath=data['filePath'],owner_id=data['owner'])
        File.delete()
        return_data = {
            'success':True,
            'description':data['filePath']+' deleted successfully'
        }
    except Exception as e:
        print e
        return_data={
            'success':False,
            'error':str(e)
        }

    rdata = json.dumps(return_data)
    return HttpResponse(rdata, content_type='application/json')

#sends back user id list and gamma for uploading a file
@csrf_exempt
def get_id_list_gamma(request):
    data = json.loads(request.body);
    id_list = []
    try:
        File = FileDB.objects.get(filePath=data['filePath'],owner_id=data['user_id'])
        return_data={
            'success':False,
            'description':'This file already exists in dropbox, please rename your file'
        }
    except Exception as e:
        for email in data['shared_list']:
            if email:
                try:
                    user = User.objects.get(email=email)
                    id_list.append(user.id)
                except Exception as e:
                    print str(e)

        try:
            user = User.objects.get(id=data['user_id'])
            return_data={
                'success':True,
                'id_list': id_list,
                'gamma': user.gamma
            }
        except Exception as e:
            return_data = {
                'success':False,
                'description':str(e)
            }

    rdata = json.dumps(return_data)
    return HttpResponse(rdata, content_type='application/json')

#Method fetches all the required parameters for sharning for the owner and sends back as response
@csrf_exempt
def get_share_params(request):
    data = json.loads(request.body)
    id_list = []
    try:
        File = FileDB.objects.get(owner_id=data['owner'],filePath=data['filePath'])
        owner = User.objects.get(id=File.owner_id)
        
        for email in data['email']:
            if email:
                try:
                    receiver = User.objects.get(email=email)
                    try: # we perform this step to check if the user is already sharing the file with owner
                        check_shared_user =  FileShare.objects.get(File_id=File,receiver_id=receiver.id)
                    except Exception as e:
                        id_list.append(receiver.id) #add only if user is not already sharing the file
                except Exception as e:
                    print str(e)

        return_data={
            'success':True,
            'fileId':File.id,
            'OC1':File.OC1,
            'C1':File.C1,
            't':File.t,
            't_new':File.t_new,
            'shared_users':id_list
        }
    except Exception as e:
        return_data={
            'success':False,
            'description':str(e)
        }

    return HttpResponse(json.dumps(return_data), content_type='application/json')


#This function is supposed to receiver file parameters and complete the file sharing job
#by re-encrypting the outer layer
@csrf_exempt
def complete_file_share(request):
    data = json.loads(request.body)
    try:
        File = FileDB.objects.get(id=data['File_id'])
        File.OC1 = data['OC1']
        File.C1 = data['C1']
        File.shared_url = data['shared_url']
        File.save()
        for receiver in data['shared_users']:
            try:
                FileShare(File_id=data['File_id'],owner_id=data['owner'],receiver_id=receiver).save()
            except Exception, e:
                raise e
        return_data={
            'success':True,
            'description':"File shared successfully"
        }
    except Exception as e:
        return_data={
            'success':False,
            'description':str(e)
        }

    return HttpResponse(json.dumps(return_data), content_type='application/json')


#Get the revoke parameters and send to the owner
@csrf_exempt
def get_revoke_params(request):
    data = json.loads(request.body)
    id_list=[]
    return_data={}

    try:
        File = FileDB.objects.get(filePath=data['filePath'],owner_id=data['owner'])
        file_share = FileShare.objects.filter(File_id=File.id).values_list('receiver_id',flat=True)
        server = User.objects.get(id=NUM_USERS)   #treat last user as server
        
        for email in data['email']:
            try:
                receiver = User.objects.get(email=email)
                if data['owner']!=receiver.id and receiver.id in file_share:    #owner can't revoke themselves, better delete the file
                        id_list.append(receiver.id)
            except Exception as e:
                print e

        if len(id_list)>0:
            return_data={
                'success':True,
                'OC0':File.OC0,
                'OC1':File.OC1,
                'C0':File.C0,
                'C1':File.C1,
                't':File.t,
                't_new':File.t_new,
                'revoke_list':id_list,
                'publicKey':server.public_rsa
            }
        else:
            return_data={
                'success':False,
                'description':"No valid users found for revoking"
            }
    except Exception as e:
        return_data={
            'success':False,
            'description':str(e)
        }

    return HttpResponse(json.dumps(return_data), content_type='application/json')


#update the file metadata and revoke users
@csrf_exempt
def revoke_users(request):
    data = json.loads(request.body)
    try:
        File = FileDB.objects.get(filePath=data['ku']['filePath'],owner_id=data['owner'])   #File record to be updated
        server = User.objects.get(id=NUM_USERS)
        
        url = "https://api-content.dropbox.com/1/files/auto"+File.filePath
        headers = {
            "Authorization": 'Bearer ' + data['access_token']
        }
        
        #process = subprocess.check_output("mkdir /tmp/"+str(data['owner']),shell=True,stderr=subprocess.STDOUT)
        fileName = str(data['owner'])+'_'+str(File.filePath.split('/').pop())   #to prevent clashes prepend owner id to filename
        localFilePath = "/tmp/"+fileName
        with open(localFilePath, 'wb') as handle:
            response = requests.get(url, headers=headers, stream=True)
            if not response.ok:
                raise Exception("File could not be downloaded from dropbox")

            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    handle.write(chunk)
                    handle.flush()

        #call the backend to update the contents
        process = subprocess.check_output(BACKEND+"mainbgw revoke "+localFilePath+" "+data['ku']['k1']+" "+data['ku']['k1_new']+" \""+server.secret_rsa+"\"", shell=True,\
                                          stderr=subprocess.STDOUT)
        
        print (process)

        #update the file to dropbox
        upload_to_dropbox(File.filePath, localFilePath, data['access_token'])

        #update the file metadata in database
        File.C0 = data['ku']['C0']
        File.C1 = data['ku']['C1']
        File.OC1 = data['ku']['OC1']
        File.t_new = data['ku']['t']
        File.save()

        #remove the users from shared database
        for receiver in data['ku']['revoke']:
            FileShare.objects.get(File_id=File.id,owner_id=data['owner'],receiver_id=receiver).delete()

        return_data={
            'success':True,
            'description':'Users revoked and file updated'
        }
    except Exception as e:
        return_data={
            'success':False,
            'description':str(e)
        }
    return HttpResponse(json.dumps(return_data), content_type='application/json')


def upload_to_dropbox(filePath, localFilePath, access_token):
    url = "https://api-content.dropbox.com/1/files_put/auto"+filePath
    
    with open(localFilePath, "rb") as handle:
        content = handle.read()
        headers = {
            "Authorization": "Bearer "+access_token,
            "Content-Length": len(content)
        }
        response = requests.put(url, headers=headers, data = content)
        if not response.ok:
            raise Exception("Upload error")


@csrf_exempt
def get_shared_files(request):
    email = request.body
    file_list = []
    try:
        user = User.objects.get(email=email)
        shared_files = FileShare.objects.filter(receiver_id=user.id).exclude(owner_id=user.id).values_list('File_id',flat=True)
        for s in shared_files:
            File = FileDB.objects.get(id=s)
            file_list.append(File.shared_url)
        return_data={
            'success':True,
            'shared_files':file_list
        }
    except Exception as e:
        return_data={
            'success':False,
            'description':str(e)
        }
    return HttpResponse(json.dumps(return_data), content_type='application/json')