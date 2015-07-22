var clientId = 'hi2bk01oe26hk8d';
var clientsecret = '6547yu998k6p99f';
var redirectUri = 'https://' + chrome.runtime.id + '.chromiumapp.org/main.html';

var CLOUD_SERVER = "http://127.0.0.1:8000/crest/"

var token_split = '---';

//some global variables for box authentication
var user_email = null;
var user_id;
var access_token;
var token_type;
var set_time;
var shared_list;
var uniqueSharedList = [];

//on starting extension check for cookies
$(document).ready(function()
{
    $("#logout").hide();
    $('#genkeys').hide();
    $("#login").click(startOauth);

    $('#logout').click(function(){
        logout();
    });

    $('#genkeys').click(function(){
        generateUbeKeys();
    });
    $('#emailSubmit').click(function(){
        shared_list = shared_list.concat($("#emailList").val().split(','));
    });

    $(document).on("click",'.share', shareFile);
    $(document).on("click", '.download', downloadFile);
    $(document).on('click', '.folder', openFolder);
    $(document).on("click", ".delete", deleteFile);
    $(document).on("click", ".revoke", revokeUser);
    $(document).on("click", "#id_submit",startUpload);
});


function logout()
{
    var url = 'https://api.dropbox.com/1/disable_access_token';
    var headers = {
        Authorization: 'Bearer ' + getAccessToken()
    };
    var args = {
        url: url,
        headers: headers,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'application/x-www-form-urlencoded',
        type: 'POST',
        dataType: 'json',
        success: function (data) {
            chrome.identity.launchWebAuthFlow({url: 'https://www.dropbox.com/logout'},
            function(responseUrl){
                console.log(responseUrl);
            });
            location.reload();
        }
    };
    $.ajax(args);
}


function getAccessToken(){
    return access_token;
}

function getUserInformation(){
    var url = "https://api.dropbox.com/1/account/info";
    var headers = {
        Authorization: 'Bearer ' + getAccessToken()
    };
    var args = {
        url: url,
        headers: headers,
        type: 'GET',
        dataType: "json",
        success: function (data) {
            var content = "<table class='table table-hover'><tbody>";
            content += "<tr><td>" + data.display_name + "</td><td></td></tr>";
            content += "<tr><td>Total Storage</td><td>" + (data.quota_info.quota/(1024*1024)).toFixed(2) + " MB</td></tr>";
            content += "<tr><td>Used Storage</td><td>" + ((data.quota_info.normal + data.quota_info.shared)/(1024*1024)).toFixed(2) + " MB</td></tr>";
            content += "</tbody></table>";
            user_email = data.email;
            $("#display_infor").html(content);
            $('#login').hide();
            $('#logout').show();
            $('#genkeys').show();
            check_add_user();
            getMetadata('/',createFolderViews);
        },
        error: function(jqXHR){
            console.log(jqXHR);
        }
    };
    $.ajax(args);
}

function startOauth(){
    var authUrl = 'https://www.dropbox.com/1/oauth2/authorize';
    authUrl += '?response_type=token&client_id='
            + encodeURIComponent(clientId)
            + '&state=authenticated'
            + '&redirect_uri=' + encodeURIComponent(redirectUri);

    chrome.identity.launchWebAuthFlow({url: authUrl, interactive: true},
    function(responseUrl) {
        access_token = responseUrl.substring(responseUrl.indexOf("access_token=") + 13,responseUrl.indexOf("&token_type"));
        getUserInformation();
    });
}

//Simple function to get metadata of folder or file
function getMetadata(path,callback){
    var url = "https://api.dropbox.com/1/metadata/auto"+path;
    var headers = {
        Authorization: 'Bearer ' + getAccessToken()
    };
    var args = {
        url: url,
        headers: headers,
        type: 'GET',
        dataType: 'json',
        success: function(data)
        {
            if(callback)
                callback(data);
            else
                console.log(data);
        },
        error: function(jqXHR){
            console.log(jqXHR);
        }
    };
    $.ajax(args);
}

//populates view with the contents of the folder opened
function createFolderViews(metadata){
    var path;
    var contents = metadata.contents;
    var table = "<table id='folder_view' class='table table-striped table-hover'><thead><th>Path: "+metadata.path+"</th><th></th><th></th></thead><tbody>";
    var tr = "<tr path=\""+metadata.path+"\"><td> <input type=\"file\" name=\"file\" id=\"upload_file\"></td>";
    tr += "<td><button class=\"btn btn-success\" name=\"submit\" id=\"id_submit\" >Upload</button></td><td></td><td></td><td></td></tr>";
    table += tr;

    for (var x in contents)
    {
        path = contents[x].path;
        if(contents[x].is_dir == true){
            tr = "<tr path='" + path + "'><td>";
            tr += path.split('/').pop() + "</td><td><button class='btn btn-warning folder'>Open Folder</button></td><td></td>" + "</tr>";
        }
        else{
            tr = "<tr path='" + path + "'><td>";
            tr += path.split('/').pop() + "</td><td><button class='btn btn-primary download'>Download</button></td>"
            tr += "<td><button class='btn btn-warning share'>Share</button></td>"
            tr += "<td><button class='btn btn-info revoke'>Revoke</button></td>"
            tr += "<td><button class='btn btn-danger delete'>Delete</button></td></tr>";
        }
        table += tr;
    }
    table += "</tbody></table>";
    $("#id_content").html(table);
}

//function to open the folder by getting metadata
function openFolder()
{
    var folderPath = $(this).closest('tr').attr('path');
    getMetadata(folderPath,createFolderViews)
}

//Simple function to download a file
function downloadFile(){
    var filePath = $(this).closest('tr').attr('path');
    var url = "https://api-content.dropbox.com/1/files/auto"+filePath;
 
    var oReq = new XMLHttpRequest();
    oReq.open("GET",url,true);
    oReq.responseType="arraybuffer";
    var auth = 'Bearer '+getAccessToken();
    oReq.setRequestHeader("Authorization",auth);
    oReq.onload = function(oEvent){
            var metadata = $.parseJSON(this.getResponseHeader('x-dropbox-metadata'));
            var enc_content = this.response;
            
            //if downloaded encrypted file with .crest extension from dropbox then decrypt by downloading metadata from server
            if(metadata.path.split('.').pop()=='crest')
            {
                //Downloading metadata from server
                var oReq = new XMLHttpRequest();
                var request_data ={
                    "filePath":filePath,
                    "owner":user_id,
                };
                oReq.open("POST",CLOUD_SERVER+'download_file_meta', true);
                oReq.responseType = "json";
                oReq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
                oReq.onload = function(oEvent)
                {
                    //on receiving metadata send contents for decryption
                    var len = enc_content.byteLength;
                    if(oReq.response.success)
                    {
                        get_pps_params(function(ppsParams){
                            common.naclModule.postMessage({ action: "decryption",
                                content: enc_content,
                                CT: oReq.response.CT,
                                km: oReq.response.km,
                                secret_rsa: oReq.response.secret_rsa,
                                ppsParams: ppsParams,
                                user_id: user_id,
                                shared_users: oReq.response.shared_users
                             });
                        });
                    }
                    else
                        alert('File Data not found on server!!');
                };
                oReq.send(JSON.stringify(request_data));
            }
            else
                console.log(String.fromCharCode.apply(null, new Uint8Array(enc_content)));
        };
        oReq.send(null);
}

function completeDownload(data)
{
    console.log(data.plaintext);
}

//upload to the current folder displayed to the user
function startUpload()
{
    $('#emailModal').modal({backdrop: 'static'});

    var folderPath = $(this).closest('tr').attr('path');
    if(folderPath.endsWith('/')==false)
        folderPath = folderPath+'/';

    //need to initialise here, by default user shares with themselves
    shared_list=[user_email];

    $('#emailModal').one('hidden.bs.modal',function(event)
    {
        var file = $("#upload_file")[0].files[0];
        if (!file){
            alert ("No file selected to upload.");
        }
        else
        {
            var oReq = new XMLHttpRequest();
            oReq.open("POST",CLOUD_SERVER+"get_id_list_gamma",true);
            oReq.responseType = "json";
            oReq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
            
            //We need to remove duplicates to prevent double addition of user, else decryption will fail
            uniqueSharedList = [];
            $.each(shared_list, function(i, el){
                if($.inArray(el, uniqueSharedList) === -1) uniqueSharedList.push(el);
            });
            
            var request_data = {
                'shared_list':uniqueSharedList,
                'user_id': user_id,
                'filePath': folderPath+file.name+".crest"
            }
            oReq.onload = function(oEvent){
                get_pps_params(function(data){
                    var reader = new FileReader();
                    reader.readAsText(file, "UTF-8");
                    var ppsParams = data;
                    reader.onload = function(evt){
                        if(oReq.response.success)
                        {
                            common.naclModule.postMessage({ action: "encryption",
                                                        filePath: folderPath+file.name+".crest",
                                                        fileType: file.type,
                                                        content: evt.target.result,
                                                        ppsParams: ppsParams,
                                                        shared_list: oReq.response.id_list,
                                                        gamma: oReq.response.gamma
                                                    });
                        }
                        else
                            console.log(oReq.response);
                    }
                });
            };
            oReq.send(JSON.stringify(request_data));
        }
    });
}

//complete upload of data on receiving encrypted text from NaCl module
//function completeUpload(filepath,data,contentLength,contentType)
function completeUpload(message)
{
    var view = new Uint8Array(message.data);
    var ciphertext = String.fromCharCode.apply(null,view);

    uploadFile(message.filePath, message.ciphertext, message.fileSize, message.fileType);
    
    var control = $("#upload_file");
    control.replaceWith( control = control.clone( true ));

    //once we have successfully uploaded file on dropbox we need to upload metadata on cloud server as well
    var data = {
        "filePath":message.filePath,
        "owner":user_id,
        "CT":message.CT,
        "shared":message.shared_users,
        "t":message.t
    };
    var oReq = new XMLHttpRequest();
    oReq.open("POST",CLOUD_SERVER+'upload_file_meta',true);
    oReq.responseType = "json";
    oReq.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    oReq.onload = function(oEvent){
        if(oReq.response.success)
            console.log("File metadata uploaded successfully.");
    };
    oReq.send(JSON.stringify(data));
}

//function to upload file to folder
function uploadFile(filepath,data,contentLength,contentType){
    var url = "https://api-content.dropbox.com/1/files_put/auto"+filepath;
    var headers = {
        Authorization: 'Bearer ' + getAccessToken(),
        contentLength: contentLength,
    };
    var args = {
        url: url,
        headers: headers,
        crossDomain: true,
        crossOrigin: true,
        processData: false,
        type: 'PUT',
        contentType: contentType,
        data : data,
        dataType: 'json',
        success: function(data)
        {
            getMetadata(filepath.substring(0, filepath.lastIndexOf("/")+1),createFolderViews);
        },
        error: function(jqXHR)
        {
            console.log(jqXHR);
        }
    };
    $.ajax(args);
}

//fucntion to delete file from dropbox
function deleteFile()
{
    var filePath = $(this).closest("tr").attr("path");
    var url = "https://api.dropbox.com/1/fileops/delete";
    var headers = {
        Authorization: 'Bearer ' + getAccessToken(),
    };
    var args = {
        url: url,
        headers: headers,
        crossDomain: true,
        crossOrigin: true,
        type: 'POST',
        data : {
            root: 'auto',
            path: filePath
        },
        dataType: 'json',
        success: function(data)
        {
            var oReq = new XMLHttpRequest();
            var request_data ={
                    "filePath":filePath,
                    "owner":user_id,
                };
            oReq.open("POST",CLOUD_SERVER+'delete_file_meta', true);
            oReq.responseType = "json";
            oReq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
            oReq.onload = function(oEvent)
            {
                getMetadata(filePath.substring(0,filePath.lastIndexOf('/')),createFolderViews);
            };
            oReq.send(JSON.stringify(request_data));
        },
        error: function(jqXHR)
        {
            console.log(jqXHR);
        }
    };
    $.ajax(args);   
}

//convert from arrayBuffer to Base64
function _arrayBufferToBase64( buffer ) {
    var binary = ''
    var bytes = new Uint8Array( buffer )
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++)
        binary += String.fromCharCode( bytes[i] );
    return window.btoa( binary );
}

//convert from Base64 to arrayBuffer
function _base64ToArrayBuffer(base64){
    var binary_string =  window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++)
        bytes[i] = binary_string.charCodeAt(i);
    return bytes.buffer;
}

//function to download pps_compress.txt from cloud server for global parameter set PPs
function get_pps_params(callback)
{
    var ppsParams = null;
    chrome.storage.local.get(['ppsParams'], function(result) {
        if ($.isEmptyObject(result))
        {
            var oReq = new XMLHttpRequest();
            oReq.open("GET", CLOUD_SERVER + 'get_pps_params', true);
            oReq.responseType = "arraybuffer";

            oReq.onload = function (oEvent) {
                ppsParams = oReq.response; // Note: not oReq.responseText
                chrome.storage.local.set({ppsParams: _arrayBufferToBase64(ppsParams)});
                callback(ppsParams);
            };

            oReq.send();
        }
        else
        {
            ppsParams = _base64ToArrayBuffer(result.ppsParams);
            callback(ppsParams);
        }
    });
}

//function to generate ube scheme private keys for recipients
function generateUbeKeys(){
    if(user_id == null)
        alert('User id not found !\nIs the django server running ?');
    else
    {
        var rsa_public_keys;
        var oReq = new XMLHttpRequest();
        oReq.open("POST", CLOUD_SERVER + 'get_rsa_public_keys', true);
        oReq.responseType = "json";
        oReq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        oReq.onload = function (oEvent) {
                rsa_public_keys = oReq.response;
                get_pps_params(function(data){
                common.naclModule.postMessage({ action: "osetup",
                                        ppsParams: data,
                                        public_keys: rsa_public_keys
                                    });
                });
            };
        oReq.send(user_id);
    }
}

//function completes keygen for owner
function completeUbeKeygen(data)
{
    delete data['action'];  //no need to send to server
    var key_data = {
        'user_id':user_id,
        'keys':data.km,
        'gamma':data.gamma
    }

    var oReq = new XMLHttpRequest();
    oReq.open("POST",CLOUD_SERVER+'add_ube_keys',true);
    oReq.responseType = "json";
    oReq.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    oReq.onload = function(oEvent){
        console.log(oReq.response);
    };
    oReq.send(JSON.stringify(key_data));
}

//Checks if user is registered in computational cloud, if not then adds to the database and fetches the user_id
function check_add_user()
{
    var oReq = new XMLHttpRequest();
    oReq.open("POST",CLOUD_SERVER+'check_add_user', true);
    oReq.responseType = "json";
    //Send the proper header information along with the request
    oReq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    oReq.onload = function(oEvent){
        user_id = oReq.response.user_id;    //set user id in javascript
        if(oReq.response.exist==false)
            generateUbeKeys();
    };
    oReq.send(user_email);
}

//Start sharing with more users
function shareFile(){
    var filePath = $(this).closest('tr').attr('path');
    // var url = "https://api.dropbox.com/1/shares/auto"+filePath;
    // var oReq = new XMLHttpRequest();
    // oReq.open("POST",url,true);
    // oReq.responseType = "json"
    // oReq.setRequestHeader("Authorization",'Bearer '+getAccessToken());
    // oReq.onload = function(oEvent){
    //     url = oReq.response.url;
    //     console.log(url);
    //     oReq.open("GET",url,true);
    //     oReq.setRequestHeader('Access-Control-Allow-Headers', '*');
    //     oReq.onload = function(oEvent){
    //         console.log(oReq.response);
    //     }
    //     oReq.send(null);
    // };
    // oReq.send(null);

    $("#emailModal").modal({backdrop: 'static'});

    shared_list = [];   //re-initialise the shared list of users

    $('#emailModal').one('hidden.bs.modal',function(event){
        if (shared_list.length>0)
        {
            var oReq = new XMLHttpRequest();
            oReq.open("POST",CLOUD_SERVER+'get_share_params',true);
            oReq.responseType = "json";
            oReq.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

            //removing duplicates
            uniqueSharedList = [];
            $.each(shared_list, function(i, el){
                if($.inArray(el, uniqueSharedList) === -1) uniqueSharedList.push(el);
            });

            var request_data = {
                'owner':user_id,
                'filePath':filePath,
                'email':uniqueSharedList
            };

            oReq.onload = function(oEvent){
                //console.log(oReq.response);
                if(oReq.response.success)
                {
                    if(oReq.response.shared_users.length>0)
                    {
                        get_pps_params(function(ppsParams){
                            common.naclModule.postMessage({
                                action: 'share',
                                ppsParams: ppsParams,
                                metadata: oReq.response
                            });
                        });
                    }
                    else
                        console.log("No valid crest users to share with");
                }
                else
                    console.log(oReq.response);
            };
            oReq.send(JSON.stringify(request_data));
        }
        else
            console.log("No users selected to share with");
    });
}

function completeShareFile(data)
{
    delete data['action'];  //no need to send to server
    data['owner']=user_id;    //set owner id before sending
    var oReq = new XMLHttpRequest();
    oReq.open("POST", CLOUD_SERVER+'complete_file_share',true);
    oReq.responseType = "json";
    oReq.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    oReq.onload = function(oEvent){
        console.log(oReq.response);
    };
    oReq.send(JSON.stringify(data));
}


//Functions to revoke a shared user
function revokeUser()
{
    var filePath = $(this).closest('tr').attr('path');

    shared_list=[]; //initialise as empty array

    $('#emailModal').modal({backdrop: 'static'});   //pop up the modal for entering email list

    $('#emailModal').one('hidden.bs.modal',function(event)
    {
        if(shared_list.length>0)    //if user saved list of revoked users
        {
            var oReq = new XMLHttpRequest();
            oReq.open("POST", CLOUD_SERVER+'get_revoke_params',true);
            oReq.responseType = "json";
            oReq.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            
            //removing duplicates
            uniqueSharedList = [];
            $.each(shared_list, function(i, el){
                if($.inArray(el, uniqueSharedList) === -1) uniqueSharedList.push(el);
            });            
            
            var request_data = {
                'email':uniqueSharedList,
                'owner':user_id,
                'filePath':filePath
            };

            oReq.onload = function(oEvent){
                if(oReq.response.success)
                {
                    get_pps_params(function(ppsParams){
                        common.naclModule.postMessage({
                            action: "revoke",
                            OC0: oReq.response.OC0,
                            OC1: oReq.response.OC1,
                            C0: oReq.response.C0,
                            C1: oReq.response.C1,
                            t: oReq.response.t,
                            publicKey:oReq.response.publicKey,
                            revoke: oReq.response.revoke_list,
                            ppsParams: ppsParams
                        });
                    });
                }
                else
                    console.log(oReq.response);
            };
            oReq.send(JSON.stringify(request_data));
        }
        else
            console.log("No users to be revoked");
    });
}

//This function is to complete the user revoke actions
function completeUserRevoke(data)
{
    console.log(data);
}