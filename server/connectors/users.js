var mongoose = require('mongoose'),
    Schema = mongoose.Schema;

// define schemas
var userSchema = new Schema({
    id: Number,
    username: {
        type: String,
        index: true
    },
    password: String,
    name: String
});

var userModel = mongoose.model('user', userSchema);

module.exports = userModel;