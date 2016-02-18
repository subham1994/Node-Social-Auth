/**
 * Created by subham_1994 on १३-०२-२०१६.
 */
var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

var userSchema = mongoose.Schema({
    local: {
        username: String,
        password: String
    },
    facebook: {
        id: String,
        token: String,
        name: String,
        email: String,
        photo: String
    },
    google: {
        id: String,
        token: String,
        name: String,
        email: String,
        photo: String
    }
});

userSchema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(9), null);
};

userSchema.methods.hasValid = function(password){
    return bcrypt.compareSync(password, this.local.password);
};

module.exports = mongoose.model('User', userSchema);