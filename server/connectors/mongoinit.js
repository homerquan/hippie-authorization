var $ = require('../lib/dollar').$,
    MongoClient = require('mongodb').MongoClient;

//TODO Configure the connection string for mongo to accept more than just local host

/**
 * Our local static db
 */
var localDb;

/**
 * Gets the static collection of "storage" that is stored within mongo db
 * @param next Calls this when completed
 */
getCollection = function(next) {
    if (typeof localDb !== "undefined") {
        //The database is already initialized
        var localCollection = localDb.collection('tokens');
        next(localCollection);
    } else {
        //We have to initialize the database and its connection
        MongoClient.connect('mongodb://127.0.0.1:27017/' + $('db').dbName, function(err, db) {
            if (err) {
                throw err;
            }
            localDb = db;
            //Add an index to the tokens
            localDb.collection('tokens').ensureIndex({
                token: 1
            }, function(err, inserted) {});
            getCollection(next);
        });
    }
};

exports.getCollection = getCollection;