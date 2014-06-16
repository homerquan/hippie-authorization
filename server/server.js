var $ = require('./lib/dollar').$,
    fs = require('fs'),
    https = require('https'),
    express = require('express'),
    passport = require('passport'),
    path = require('path'),
    connectors = require('./connectors'),
    oauth2 = require('./lib/oauth2'),
    handlers = require('./handlers');

// load common components
require('./lib/allLoader').loadDollar();

// Passport configuration
require('./lib/auth');


//Pull in the mongo store if we're configured to use it
//else pull in MemoryStore for the session configuration
var sessionStorage;
if ($('session').type === 'MongoStore') {
    var MongoStore = require('connect-mongo')(express);
    console.log('Using MongoDB for the Session');
    sessionStorage = new MongoStore({
        db: $('session').dbName
    });
} else if ($('session').type === 'MemoryStore') {
    var MemoryStore = express.session.MemoryStore;
    console.log('Using MemoryStore for the Session');
    sessionStorage = new MemoryStore();
} else {
    //We have no idea here
    throw new Error("Within config/index.js the session.type is unknown: " + $('session').type)
}

//Pull in the mongo store if we're configured to use it
//else pull in MemoryStore for the database configuration
if ($('db').type === 'mongodb') {
    console.log('Using MongoDB for the data store');
} else if ($('db').type === 'db') {
    console.log('Using MemoryStore for the data store');
} else {
    //We have no idea here
    throw new Error("Within config/index.js the connectors.type is unknown: " + $('db').type);
}

// Express configuration
var app = express();
app.set('view engine', 'ejs');
app.use(express.logger());
app.use(express.cookieParser());
app.use(express.urlencoded());
app.use(express.json());

//Session Configuration
app.use(express.session({
    secret: $('session').secret,
    store: sessionStorage,
    key: "authorization.sid",
    cookie: {
        maxAge: $('session').maxAge
    }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);

// Catch all for error messages.  Instead of a stack
// trace, this will log the json of the error message
// to the browser and pass along the status with it
app.use(function(err, req, res, next) {
    if (err) {
        res.status(err.status);
        res.json(err);
    } else {
        next();
    }
});



app.get('/', handlers.site.index);
app.get('/login', handlers.site.loginForm);
app.post('/login', handlers.site.login);
app.get('/logout', handlers.site.logout);
app.get('/account', handlers.site.account);

app.get('/dialog/authorize', oauth2.authorization);
app.post('/dialog/authorize/decision', oauth2.decision);
app.post('/oauth/token', oauth2.token);

app.get('/api/userinfo', handlers.user.info);
app.get('/api/clientinfo', handlers.client.info);

// Mimicking google's token info endpoint from
// https://developers.google.com/accounts/docs/OAuth2UserAgent#validatetoken
app.get('/api/tokeninfo', handlers.token.info);

//static resources for stylesheets, images, javascript files
app.use(express.static(path.join(__dirname, 'public')));

//From time to time we need to clean up any expired tokens
//in the database
setInterval(function() {
    connectors.accessTokens.removeExpired(function(err) {
        if (err) {
            console.error("Error removing expired tokens");
        }
    });
}, $('db').timeToCheckExpiredTokens * 1000);

//TODO: Change these for your own certificates.  This was generated
//through the commands:
//openssl genrsa -out privatekey.pem 1024
//openssl req -new -key privatekey.pem -out certrequest.csr
//openssl x509 -req -in certrequest.csr -signkey privatekey.pem -out certificate.pem
var options = {
    key: fs.readFileSync(path.join(__dirname, 'var/certs/privatekey.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'var/certs/certificate.pem'))
};

// Create our HTTPS server listening on port 8003.
https.createServer(options, app).listen($('config').PORT);
console.log("OAuth 2.0 Authorization Server started on port " + $('config').PORT);