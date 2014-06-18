/*
 * using this to concertrate all global vars and functions
 * For performance, only put most neccessary GLOBAL vars here
 */

var _ = require('underscore'),
	env = process.env.NODE_ENV || 'development',
	defaultConfig = require('../config/default.json'),
	envConfig = require('../config/' + env + '.json'),
	mongoose = require('mongoose');

var config = _.extend(defaultConfig, envConfig);

mongoose.connect('mongodb://' + config.MONGO_HOST + ':' + config.MONGO_PORT + '/' + config.MONGO_DB);

var token = {
	expiresIn: 3600,
	calculateExpirationDate: function() {
		return new Date(new Date().getTime() + (this.expiresIn * 1000));
	},
	authorizationCodeLength: 16,
	accessTokenLength: 256,
	refreshTokenLength: 256
};

var db = {
	timeToCheckExpiredTokens: 3600,
	type: "mongodb",
	dbName: "hippie-demo"
};


var session = {
	type: "MemoryStore",
	maxAge: 3600000 * 24 * 7 * 52,
	//TODO You need to change this secret to something that you choose for your secret
	secret: "A Secret That Should Be Changed",
	dbName: "Session"
};

exports.all = {
	config: config,
	token: token,
	db: db,
	session: session,
	mongoose: mongoose
};