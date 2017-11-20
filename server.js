//Express module
var express = require('express');           

//creates an Express application. The express() funciton is a top-level function exported by the express module.
var app = express();

// libsodium crytpo magic
var sodium = require('sodium').api;

var bodyParser = require('body-parser');                
var http = require('http');
var https = require('https');
var request = require('request');
var logger = require("./utils/logger");
var mysql = require('mysql');
var uuid = require('node-uuid');
var MongoClient = require('mongodb').MongoClient
    , assert = require('assert');

// the websocket
var WebSocket = require('ws');


var fs = require('fs');


var connections = {};
var count = 0;


//these parameters are needed to connect to DB; used by almost every route
var dbUser = "mootiadmin";
var dbPassword = "DevPassword$1";
var db = "mooti";
var dbhost ="mootidev.c5yxa5wex9tp.us-west-1.rds.amazonaws.com";


var MONGODBHOST = "54.67.113.149";

// configure app to use bodyParser(); this will let us get the data from a POST
app.use(bodyParser.json({limit: '50mb'}));

// disable caching for all calls
app.use(function (req, res, next) {
    res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.header('Expires', '-1');
    res.header('Pragma', 'no-cache');
    res.header('Content-type', 'application/json');
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('charset', 'utf-8');
    next();
});





var server = http.createServer(app);
var wss = new WebSocket.Server({ server });


/*
// generate our set of keys for this server
// used to generate the keys for the file

var serverKeys = sodium.crypto_box_keypair();
var secretKey = serverKeys.secretKey;
var publicKey = serverKeys.publicKey;

console.log('SecretKey =' + new Buffer(secretKey, 'binary').toString('base64'));
console.log('PublicKey = ' + new Buffer(publicKey, 'binary').toString('base64'));


var keys = {
    "secretkey": new Buffer(secretKey, 'binary').toString('base64'),
    "publicKey": new Buffer(publicKey, 'binary').toString('base64')
};

var readKeys = function(){
    // And then, to read it...
    keys = require("./filename.json");
    console.log('file == ' + JSON.stringify(keys));
};
console.log('writing');
fs.writeFile( "filename.json", JSON.stringify( keys ), "utf8", readKeys );
console.log('done');
*/



var keys = require("./filename.json");


wss.on('connection', function connection(ws, req) {
    //const location = url.parse(req.url, true);
    // You might use location.query.access_token to authenticate or share sessions
    // or req.headers.cookie (see http://stackoverflow.com/a/16395220/151312)

    count++

    console.log('connection established count = ' + count);
    //connections[count] =  ws;



    //console.log('Connections ==> ' + count);

    ws.on('message', function incoming(message) {
        console.log('received: %s', message);


        var data = JSON.parse(message);
        console.log('client type = ' + data.clientType);
        if(data.clientType == 'browser'){

            var requestType = data.requestType;
            // login request qrcode
            if(requestType == 'login') {

                var browserKeyPair = sodium.crypto_box_keypair();
                var browserSecretKey = browserKeyPair.secretKey;
                var browserPublicKey = browserKeyPair.publicKey;

                var browserKeys = {
                    "secretkey": new Buffer(browserSecretKey, 'binary').toString('base64'),
                    "publicKey": new Buffer(browserPublicKey, 'binary').toString('base64')
                };
                connections['keys'+browserKeys.publicKey] = browserKeys;
                connections[browserKeys.publicKey] = ws;

                // this is a request from a browser
                // get the type of request being sent
                var outgoingMessage;
                var requestType = data.requestType;


                // this is a login request so there are no keys yet assgined to this browser session
                outgoingMessage = {
                    'requestType': 'login',
                    'secret': 'login' + count,
                    'session': browserKeys.publicKey,
                    "host": "localhost:8000",
                    'connectionID': count
                };


                console.log('Sending ' + outgoingMessage + ' to connection id = ' + count);
                connections[browserKeys.publicKey].send(JSON.stringify(outgoingMessage));
            }
            else if(requestType == 'newFolder'){
                //{"clientType":"browser","requestType":"newFolder","folderName":"yadaFolder","browserId":"1","clientId":"e/7uOgt07U3WfOPENWLvjZxT01u8BPAz/NfP1ysQ2XY=","callback_id":1}
                var browserId = data.browserId;
                var clientId = data.clientId;
                var folderName = data.folderName;


                var message = {newFolder: {folderID: folderName}};


                var plainText = Buffer.from(JSON.stringify(message));
                var nonce = Buffer.allocUnsafe(sodium.crypto_box_NONCEBYTES);
                sodium.randombytes_buf(nonce);

                //var cipherMsg = sodium.crypto_box(plainText, nonce, new Buffer(keys.publicKey, 'base64'), new Buffer(keys.secretkey, 'base64'))

                //console.log("cipher text ==" + cipherMsg)


                var cipherMsg = sodium.crypto_box(plainText, nonce, new Buffer(clientId, 'base64'), new Buffer(keys.secretkey, 'base64'));

                console.log('Cipher Message = ' + cipherMsg);
                var encodedMessage = new Buffer(cipherMsg.slice(16), 'binary').toString('base64');
                //var encodedMessage = Buffer.from(cipherMsg, 0, cipherMsg.length).toString('base64');


                console.log('encoded message = ' + encodedMessage);



                var responseMessage = {'clientToClient':{'sender': keys.publicKey, 'message': encodedMessage, 'nonce':new Buffer(nonce, 'binary').toString('base64')}};

                console.log('sending: ' + JSON.stringify(responseMessage));
                connections[clientId].send(JSON.stringify(responseMessage));


            }
        }
        else
        {
            //{"clientToServerSender":{"message":"lnbudTZ9J4izeVZt6UlHrn3msvSotEBLeYpUvcx5tN7Oclr9FNsl88IMryHs3RuY3VKsW7JZ+VggidEl41UipkwAecXI2cA=","nonce":"7hs9lczaQpey7eJPzENu2jPppLphHaEw","sender":"tmtuGZ9nlhNlrLHulLVlTXPruoOj47DPlmtP1BeisV4="}}
            var clientToServerSender = data.clientToServerSender;
            if(clientToServerSender != undefined){
                var nonce = new Buffer(clientToServerSender.nonce, 'base64');
                var senderPubkey = new Buffer(clientToServerSender.sender, 'base64');
                var message = new Buffer(clientToServerSender.message, 'base64');
                var recipient = clientToServerSender.recipient;


                // once we have pubkey, we will use this to identify the websocket connection

                console.log("Message == " + new Buffer(clientToServerSender.message, 'base64'));
                connections[clientToServerSender.sender] = ws;

                var plainMessage = sodium.crypto_box_open(Buffer.concat([Buffer.alloc(16), message], 16+message.length),nonce,senderPubkey, new Buffer(keys.secretkey, 'base64'));

                var response = JSON.parse(plainMessage);


                var filledIdRequest = response.filledIdRequest;
                if(filledIdRequest != undefined){
                    var secret = filledIdRequest.secret;
                    if(secret.indexOf('login') !== -1){
                        //var browserId = secret.substr(5, 1);  // this only supports 9 connections refactor later



                        // send a message to the broswer that the user has logged in
                        connections[recipient].send(JSON.stringify({message:"user logged in", connectionId: browserId, clientId: clientToServerSender.sender}));

                        var plainText = Buffer.from('"success"');
                        nonce = Buffer.allocUnsafe(sodium.crypto_box_NONCEBYTES);
                        sodium.randombytes_buf(nonce);

                        //var cipherMsg = sodium.crypto_box(plainText, nonce, new Buffer(keys.publicKey, 'base64'), new Buffer(keys.secretkey, 'base64'))

                        //console.log("cipher text ==" + cipherMsg);


                        var cipherMsg = sodium.crypto_box(plainText, nonce, senderPubkey, new Buffer(keys.secretkey, 'base64'));

                        console.log('Cipther Message = ' + cipherMsg);
                        var encodedMessage = new Buffer(cipherMsg.slice(16), 'binary').toString('base64');
                        //var encodedMessage = Buffer.from(cipherMsg, 0, cipherMsg.length).toString('base64');


                        console.log('encoded message = ' + encodedMessage);



                        var responseMessage = {'serverToClient':{'message': encodedMessage, 'nonce':new Buffer(nonce, 'binary').toString('base64')}};

                        console.log('sending: ' + JSON.stringify(responseMessage));
                        ws.send(JSON.stringify(responseMessage));




                    }
                }
                console.log('Decrypted Message == ' + plainMessage)

            }

            var clientToClient = data.clientToClient;
            if(clientToClient != undefined){
                var nonce = new Buffer(clientToClient.nonce, 'base64');
                var senderPubkey = new Buffer(clientToClient.sender, 'base64');
                var message = new Buffer(clientToClient.message, 'base64');
                var recipient = clientToClient.recipient;


                var browserkeys = connections['keys'+recipient];

                var plainMessage = sodium.crypto_box_open(Buffer.concat([Buffer.alloc(16), message], 16+message.length),nonce,senderPubkey, new Buffer(browserkeys.secretkey, 'base64'));

                console.log("Recevied message = " + plainMessage);
                var response = JSON.parse(plainMessage);

                var folderSecretKey = response.folderSecretKey;
                if(folderSecretKey != undefined){
                    var folderID = response.folderID;

                    var res = writeFolder(folderID, folderSecretKey, clientToClient.sender);
                    console.log(res);
                }

                var folderCreate = {message: 'Folder Created!!'};
                var connection = connections[recipient];
                connection.send(JSON.stringify(folderCreate));

            }

            var clientToServer = data.clientToServer;
            if(clientToServer != undefined){
                console.log('ignoring this message');
                /*
                var nonce = new Buffer(clientToServer.nonce, 'base64');
                var senderPubkey = new Buffer(clientToServer.sender, 'base64');
                var message = new Buffer(clientToServer.message, 'base64');


                var plainMessage = sodium.crypto_box_open(Buffer.concat([Buffer.alloc(16), message], 16+message.length),nonce,senderPubkey, new Buffer(keys.secretkey, 'base64'));

                console.log("Recevied message = " + plainMessage);
                var response = JSON.parse(plainMessage);
                */
            }
        }
    });

    //ws.send('something');
});

server.listen(8080, function listening() {
    console.log('Listening on %d', server.address().port);
});




function writeFolder(folderID, folderKey, clientId)
{
    console.log(folderID + " " + folderKey + " " + clientId)
    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/fileshare';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        var response;
        if(err == null) {
            console.log("Connected successfully to server");
            // set the collection
            var folders = db.collection('folders');


            var nonce = Buffer.allocUnsafe(sodium.crypto_stream_NONCEBYTES);

            // create the document
            var folder = {folderID: folderID, folderKey :folderKey, owner : clientId, nonce:nonce.toString('base64')};
            folders.insertOne(folder, function(err, r){


                if(err == null){
                    response = {status : 'success'};


                }
                else{
                    response = {status :'FAILURE', message : 'insert failed ' +  err};
                }

                return  response;

            });
        }
        else{
            response = {status :'FAILURE', message : 'DB connection error ' +  err};
        }
        db.close();

        return response;
    });
}

// Pseudo config, because we don't use real config files; would be too easy obviously
var port = process.env.PORT || 8383;        // set our port

// get an instance of the express Router object
var router = express.Router();   


// ROUTES FOR OUR API
// =============================================================================

// test route to make sure everything is working (accessed at GET http://localhost:8080/)
router.get('/', function (req, res) {
    //this route does not require any parameters as input
    res.json({message: 'MOOTI API SERVER'});
});




//create post method for route '/pubkey'
router.route('/pubkey').post(function (req, res) {

    res.send(keys.publicKey);

});



//create post method for route '/folders'
router.route('/folders').post(function (req, res) {
    var senderPubKey = req.body.senderPubKey;

    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/fileshare';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        if(err == null) {
            console.log("Connected successfully to server");
        }
        else{
            res.json({classname : 'folders', status :'FAILURE', message : 'DB connection error ' +  err});
        }

        var folders = db.collection('folders').find({'owner': senderPubKey}).toArray(function(err, folders) {
            if (err) throw err;
            console.log(folders);
            res.json({status : 'success', folders: folders});
            db.close();
        });




        db.close();
    });

});

//create post method for route '/folders'
router.route('/files').post(function (req, res) {
    var owner = req.body.owner;
    var folderID = req.body.folderID


    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/fileshare';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        if(err == null) {
            console.log("Connected successfully to server");
        }
        else{
            res.json({classname : 'files', status :'FAILURE', message : 'DB connection error ' +  err});
        }

        var files = db.collection('files').find({'owner': owner, 'folderID': folderID},{fileID:1}).toArray(function(err, files) {
            if (err) throw err;
            console.log(files);
            res.json({status : 'success', files: files});
            db.close();
        });




        db.close();
    });

});


//create post method for route '/shareFolders'
router.route('/shareFolder').post(function (req, res) {
    var ownerPubkey = req.body.ownerPubkey;
    var folderID = req.body.folderID;
    var shareWithPubkey = req.body.shareWithPubkey;


    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/fileshare';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        if(err == null) {
            console.log("Connected successfully to server");
        }
        else{
            res.json({classname : 'folders', status :'FAILURE', message : 'DB connection error ' +  err});
        }

        var folders = db.collection('folders').find({'owner': ownerPubkey, 'folderID': folderID}).toArray(function(err, folders) {
            if (err) {
                res.json({status: 'failure', error: err});
            }
            else {
                console.log(folders);


                folders1 = db.collection('folders');
                var folder = {folderID: folderID, folderKey :folders[0].folderKey, owner : shareWithPubkey};
                folders1.insertOne(folder, function(err, r){

                });

                res.json({status: 'success', folders: folder});
            }
            //db.close();
        });
        //db.close();
    });

});

//create post method for route '/getFile'
router.route('/updateUser').post(function (req, res) {
    //var senderPubKey = req.body.senderPubKey;
    var userName = req.body.userName;
    var browserPrint = req.body.browserPrint;
    //var fileBase64Data = req.body.fileBase64Data;

    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/fileshare';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        if(err == null) {
            console.log("Connected successfully to server");
        }
        else{
            res.json({classname : 'poscoLogin', status :'FAILURE', message : 'DB connection error ' +  err});
        }


        users = db.collection('users');
        // create the document
        var user = {userName: userName,  browserPrint: browserPrint};
        users.insertOne(user, function(err, r){


            if(err == null){
                console.log('create user success');
                res.json({status: 'success', code: 0});


            }
            else{
                console.log('create user error = ' + err);
                res.json({status: 'success', code: 1, error: err});
            }
            //return  response;

            db.close();
        });

    });

});



//create post method for route '/getFile'
router.route('/poscoLogin').post(function (req, res) {
    //var senderPubKey = req.body.senderPubKey;
    var userName = req.body.userName;
    var browserPrint = req.body.browserPrint;
    //var fileBase64Data = req.body.fileBase64Data;

    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/fileshare';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        if(err == null) {
            console.log("Connected successfully to server");
        }
        else{
            res.json({classname : 'poscoLogin', status :'FAILURE', message : 'DB connection error ' +  err});
        }

        var users = db.collection('users').find({'userName': userName}).toArray(function(err, users) {

            console.log('users table = ' + users);
            if (err) {
                res.json({status: 'failure', error: err});
            }
            else {
                if(users == undefined || users == ""){


                    /*
                    users = db.collection('users');
                    // create the document
                    var user = {userName: userName,  browserPrint: browserPrint};
                    users.insertOne(user, function(err, r){


                        if(err == null){
                            console.log('create user success');
                            res.json({status: 'success', message: 'user created'});


                        }
                        else{
                            console.log('create user error = ' + err);
                            res.json({status: 'success', message: 'create user error = ' + err});
                        }
                        //return  response;



                        db.close();
                    });
                    */

                    console.log('user not found');

                    res.json({status: 'success', code: 2});
                }
                else {

                    var found = false;
                    for(x=0; x < users.length; x++){

                        console.log("comparing " + user[x].browserPrint + " to " + browserPrint);
                        if(users[x].browserPrint == browserPrint){

                            console.log("found fingerprint");
                            found = true;
                            break;
                        }

                    }

                    if(!found){
                        console.log('user found different finger print');
                        res.json({status: 'success', code: 1});
                    }
                    else{
                        res.json({status: 'success', code: 0});
                    }

                }

            }
            db.close();
        });

        //db.close();
    });

});





//create post method for route '/getFile'
router.route('/getFile').post(function (req, res) {
    var senderPubKey = req.body.senderPubKey;
    var folderID = req.body.folderID;
    var fileID = req.body.fileID;
    //var fileBase64Data = req.body.fileBase64Data;

    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/fileshare';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        if(err == null) {
            console.log("Connected successfully to server");
        }
        else{
            res.json({classname : 'getFile', status :'FAILURE', message : 'DB connection error ' +  err});
        }

        var folders = db.collection('folders').find({'owner': senderPubKey, 'folderID': folderID}).toArray(function(err, folders) {
            if (err) {
                res.json({status: 'failure', error: err});
            }
            else {

                var secretKey = new Buffer(folders[0].folderKey, 'base64');
                var nonce = new Buffer(folders[0].nonce, 'base64');
                //var nonce = Buffer.allocUnsafe(sodium.crypto_stream_NONCEBYTES);
                // Encrypt the message
                //var plainMsg = Buffer.from(fileBase64Data);
                //var cipherMsg = sodium.crypto_stream_xor(plainMsg,nonce,secretKey);
                //if( !cipherMsg ) {
                //    throw("secret key encrypt error");
                //}
                //console.log(cipherMsg);


                var files = db.collection('files').find({'owner': senderPubKey, 'folderID': folderID, 'fileID':fileID}).toArray(function(err, files) {


                    //console.log(files);
                    if(err == null){
                        //console.log('got the  file ' + JSON.stringify(files[0]));
                        //var cipherMsg = new Buffer.from(files[0].data, 'base64');
                        //console.log('cipherData == ' + files[0].data);




                        var cipherMsg = new Buffer(files[0].data, 'base64');

                        console.log('cipherMsg == ' + cipherMsg);
                        var plainMsg2 = sodium.crypto_stream_xor(cipherMsg,nonce,secretKey);
                        if( !plainMsg2 ) {
                            console.log("secret key decrypt error");
                        }
                        console.log(plainMsg2.toString());

                        res.json({status: 'success', data: plainMsg2.toString()});


                    }
                    else{

                        res.json({status: 'error', error: err});
                    }

                });

            }
            db.close();
        });

        //db.close();
    });

});




//create post method for route '/addFile'
router.route('/addFile').post(function (req, res) {
    var senderPubKey = req.body.senderPubKey;
    var folderID = req.body.folderID;
    var fileID = req.body.fileID;
    var fileBase64Data = req.body.fileBase64Data;

    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/fileshare';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        if(err == null) {
            console.log("Connected successfully to server");
        }
        else{
            res.json({classname : 'folders', status :'FAILURE', message : 'DB connection error ' +  err});
        }

        var folders = db.collection('folders').find({'owner': senderPubKey, 'folderID': folderID}).toArray(function(err, folders) {
            if (err) {
                res.json({status: 'failure', error: err});
            }
            else {
                console.log(folders);
                var secretKey = new Buffer(folders[0].folderKey, 'base64');
                var nonce = Buffer(folders[0].nonce, 'base64');
                //var nonce = Buffer.allocUnsafe(sodium.crypto_stream_NONCEBYTES);
                // Encrypt the message
                var plainMsg = Buffer.from(fileBase64Data);
                var cipherMsg = sodium.crypto_stream_xor(plainMsg,nonce,secretKey);
                if( !cipherMsg ) {
                    throw("secret key encrypt error");
                }
                console.log(cipherMsg);


                var files = db.collection('files');

                // create the document
                var file = {folderID: folderID, fileID :fileID, owner : senderPubKey, data:cipherMsg.toString('base64')};
                files.insertOne(file, function(err, r){


                    if(err == null){
                        console.log('insert file success');


                    }
                    else{
                        console.log('insert file error = ' + err);
                    }
                    //return  response;


                    db.close();
                });


// Decrypt the message
                var plainMsg2 = sodium.crypto_stream_xor(cipherMsg,nonce,secretKey);
                if( !plainMsg2 ) {
                    throw("secret key decrypt error");
                }
                console.log(plainMsg2.toString());

                res.json({status: 'success', folders: folders});
            }
            //db.close();
        });

        //db.close();
    });

});


// MOEDA Service
//create post method for route '/createUser'
router.route('/createUser').post(function (req, res) {

    console.log('Received: ' + JSON.stringify(req.body));
    var pubKey = req.body.pubKey;
    var email = req.body.email;
    var pin = req.body.pin;

    // connect to mooti db
    // Connection URL
    var url = 'mongodb://' + MONGODBHOST + ':27017/mooti';

// Use connect method to connect to the server
    MongoClient.connect(url, function(err, db) {

        if(err == null) {
            console.log("Connected successfully to server");
            // set the collection
            var users = db.collection('users');

            // create the document
            var user = {pubKey: pubKey, email :email, pin : pin};
            users.insertOne(user, function(err, r){
                if(err == null){
                    res.json({status : 'success'});
                    return;
                }
                else{
                    res.json({classname : 'createUser', status :'FAILURE', message : 'insert failed ' +  err});
                }

            });
        }
        else{
            res.json({classname : 'createUser', status :'FAILURE', message : 'DB connection error ' +  err});
        }


        db.close();
    });
});





// REGISTER OUR ROUTES -------------------------------
// all of our routes will be prefixed with /api
app.use('/', router);

// START THE SERVER
// =============================================================================
app.listen(port);
logger.info('Server running on port ' + port);

