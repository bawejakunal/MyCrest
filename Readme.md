###WeShare: A Coercion-Resistant and Scalable Storage Cloud

**NOTE:** This particular implementation is meant for local, small-scaled deployment of the application for demo purposes.

MyCrest is a prototype developed for **WeShare: A Coercion-Resistant and Scalable Storage Cloud** over [Dropbox](http://www.dropbox.com). The poster for WeShare can be accessed at [WeShare](http://www.ieee-security.org/TC/SP2015/posters/paper_8.pdf). This application is intended to demonstrate the concept of coercion resistant and scalable storage wherein a user can upload and share files over the cloud without having to rely on the service provider for the security of stored data along with the added advantage of low computational costs for sharing the encrypted files with users in comparison to the existing similar solutions.

####Working Description
MyCrest has been implemented as a browser extension for Google Chrome browser. The application runs on top of dropbox, which is used as the underlying cloud storage for encrypted files of the user and the files shared with other users. To use this developemental version of MyCrest please follow the following steps:

#####MySQL Database Setup
Before getting started with the application, it is **important to setup the corresponding MySQL Database** that you intend to use with your application. Please follow the given steps to setup the database for MyCrest:

1. Type `mysql -u root -p` to connect to your local MySQL server or any other MySQL server that you might be using.
2. `create database crest` within your MySQL server. Do not use any other name as the Django framework will particularly look for this file while creating the database tables.
3. **Provide database access to cloud application**. Open the file `MyCrest/cloud/cloud/settings.py` and update the `USER`, `PASSWORD`, `HOST` and `PORT` fields for the `DATABASES`.
4. Navigate to `MyCrest/cloud` in the terminal.
5. `python manage.py makemigrations` to generate updated database rules based on the ones described in `MyCrest/cloud/crest/models.py`. This is a django framework utility and needs to be done only once.
6. `python manage.py migrate` to create/update the MySQL database tables.

#####Running the Python Django Server
It is important that the server is running properly and the first time setup of public parameters has been done before the users start using the extension.

1. Navigate to `MyCrest/cloud` in the terminal.
2. `python manage.py runserver 0.0.0.0:8000` to launch the cloud server protoype running with python based django framework.
3. To check the correct running of the server, open `http://localhost:8000/crest/` in the browser.
4. **Set up public parameters**. Please note that this step needs to be done only once, repeating it over and over will overwrite the public parameters in the database and render the existing data of cloud users useless. Enter the url `http://localhost:8000/crest/server_setup` in the browser's navigation bar, this will trigger the setup function at django server and report success upon completion. If completed sucessfully it does not needs to be repeated again.

#####Loading the extension in Google Chrome
The MyCrest Chrome extension is based on the [Native Client Module](https://developer.chrome.com/native-client) which enables running of apps/extensions backed by C/C++ languages within the browser. Follow the steps below to load the application into the browser:

1. Open a new tab in Google Chrome and navigate to `chrome://extensions`
2. Click on `Load Unpacked Extension` and select the location of `MyCrest` folder.
3. Alternatively user can also pack the application and drag and drop the generated `.crx` file into the tab to load the extension in the browser.
4. Click on the `box icon` on top right to launch the application.
5. Provide your `Dropbox Credentials` to authenticate the extension to be used in conjunction with `Dropbox`.