var passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    BasicStrategy = require('passport-http').BasicStrategy,
    ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy,
    BearerStrategy = require('passport-http-bearer').Strategy,
    connectors = require('../connectors');

/**
 * LocalStrategy
 *
 * This strategy is used to authenticate users based on a username and password.
 * Anytime a request is made to authorize an application, we must ensure that
 * a user is logged in before asking them to approve the request.
 */
passport.use(new LocalStrategy(
    function(username, password, cb) {
        connectors.users.findOne({
            username: username
        }, function(err, user) {
            if (err) {
                return cb(err);
            }
            if (!user) {
                return cb(null, false);
            }
            if (user.password != password) {
                return cb(null, false);
            }
            return cb(null, user.toObject());
        });
    }
));

/**
 * BasicStrategy & ClientPasswordStrategy
 *
 * These strategies are used to authenticate registered OAuth clients.  They are
 * employed to protect the `token` endpoint, which consumers use to obtain
 * access tokens.  The OAuth 2.0 specification suggests that clients use the
 * HTTP Basic scheme to authenticate.  Use of the client password strategy
 * allows clients to send the same credentials in the request body (as opposed
 * to the `Authorization` header).  While this approach is not recommended by
 * the specification, in practice it is quite common.
 */
passport.use(new BasicStrategy(
    function(username, password, cb) {
        connectors.clients.findByClientId(username, function(err, client) {
            if (err) {
                return cb(err);
            }
            if (!client) {
                return cb(null, false);
            }
            if (client.clientSecret != password) {
                return cb(null, false);
            }
            return cb(null, client);
        });
    }
));

/**
 * Client Password strategy
 *
 * The OAuth 2.0 client password authentication strategy authenticates clients
 * using a client ID and client secret. The strategy requires a verify callback,
 * which accepts those credentials and calls cb providing a client.
 */
passport.use(new ClientPasswordStrategy(
    function(clientId, clientSecret, cb) {
        connectors.clients.findByClientId(clientId, function(err, client) {
            if (err) {
                return cb(err);
            }
            if (!client) {
                return cb(null, false);
            }
            if (client.clientSecret != clientSecret) {
                return cb(null, false);
            }
            return cb(null, client);
        });
    }
));

/**
 * BearerStrategy
 *
 * This strategy is used to authenticate either users or clients based on an access token
 * (aka a bearer token).  If a user, they must have previously authorized a client
 * application, which is issued an access token to make requests on behalf of
 * the authorizing user.
 */
passport.use(new BearerStrategy(
    function(accessToken, cb) {
        connectors.accessTokens.find(accessToken, function(err, token) {
            if (err) {
                return cb(err);
            }
            if (!token) {
                return cb(null, false);
            }
            if (new Date() > token.expirationDate) {
                connectors.accessTokens.delete(accessToken, function(err) {
                    return cb(err);
                });
            } else {
                if (token.userID != null) {
                    connectors.users.findOne({
                        id: token.userID
                    }, function(err, user) {
                        if (err) {
                            return cb(err);
                        }
                        if (!user) {
                            return cb(null, false);
                        }
                        // to keep this example simple, restricted scopes are not implemented,
                        // and this is just for illustrative purposes
                        var info = {
                            scope: '*'
                        };
                        return cb(null, user, info);
                    });
                } else {
                    //The request came from a client only since userID is null
                    //therefore the client is passed back instead of a user
                    connectors.clients.find(token.clientID, function(err, client) {
                        if (err) {
                            return cb(err);
                        }
                        if (!client) {
                            return cb(null, false);
                        }
                        // to keep this example simple, restricted scopes are not implemented,
                        // and this is just for illustrative purposes
                        var info = {
                            scope: '*'
                        };
                        return cb(null, client, info);
                    });
                }
            }
        });
    }
));

// Register serialialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTPS request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.

passport.serializeUser(function(user, cb) {
    cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
    //move to handler
    connectors.users.findOne({
        id: id
    }, function(err, user) {
        cb(err, user.toObject());
    });
});