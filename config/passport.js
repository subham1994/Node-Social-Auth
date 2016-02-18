/**
 * Created by subham_1994 on १४-०२-२०१६.
 */
var localStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var User = require('../app/models/user');
var oAuth = require('./auth');
module.exports = function(passport) {
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    passport.use('local-signup', new localStrategy({
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true
        },
        function(req, username, password, done){
            process.nextTick(function() {
                User.findOne({'local.username': username}, function(err, user) {
                    if(err) {
                        return done(err);
                    }
                    if(user) {
                        return done(null, false, req.flash('signupMessage', 'email already taken'));
                    }
                    if(!req.user) {
                        var newUser = new User();
                        newUser.local.username = username;
                        newUser.local.password = newUser.generateHash(password);
                        newUser.save(function(err) {
                            if(err) { throw err; }
                            return done(null, newUser);
                        });
                    } else {
                        var user = req.user;
                        user.local.username = username;
                        user.local.password = user.generateHash(password);
                        user.save(function(err) {
                            if(err) { throw err; }
                            return done(null, user);
                        });
                    }
                });
            });
        }
    ));

    passport.use('local-login', new localStrategy({
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true
        },
        function(req, username, password, done){
            process.nextTick(function() {
                User.findOne({'local.username': username}, function(err, user) {
                    if(err) {
                        return done(err);
                    }
                    if(!user) {
                        return done(null, false, req.flash('loginMessage', 'No account found !!'));
                    }
                    if(!user.hasValid(password)) {
                        return done(null, false, req.flash('loginMessage', 'invalid username or password !!'));
                    }
                    return done(null, user);
                });
            });
        }
    ));

    passport.use(new FacebookStrategy({
            clientID: oAuth.facebookAuth.clientId,
            clientSecret: oAuth.facebookAuth.clientSecret,
            callbackURL: oAuth.facebookAuth.callbackUrl,
            profileFields: ['id', 'email', 'gender', 'name', 'picture.width(400).height(400)'],
            passReqToCallback: true
        },
        function(req, accessToken, refreshToken, profile, done) {
            process.nextTick(function() {
                if(!req.user) {
                    User.findOne({'facebook.id': profile.id}, function(err, user) {
                        if(err) {
                            return done(err);
                        }
                        if(user) {
                            if(!user.token) {
                                user.token = accessToken;
                                user.save(function(err) {
                                    if(err) {
                                        throw err;
                                    }
                                });
                            }
                            return done(null, user);
                        } else {
                            var newUser = new User();
                            newUser.facebook.id = profile.id;
                            newUser.facebook.token = accessToken;
                            newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                            newUser.facebook.email = profile.emails[0].value;
                            newUser.facebook.photo = profile.photos[0].value;
                            newUser.save(function(err) {
                                if(err) {
                                    throw err;
                                }
                                return done(null, newUser);
                            });
                        }
                    });
                } else {
                    var user = req.user;
                    user.facebook.id = profile.id;
                    user.facebook.token = accessToken;
                    user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                    user.facebook.email = profile.emails[0].value;
                    user.facebook.photo = profile.photos[0].value;
                    user.save(function(err) {
                        if (err) {
                            throw err;
                        }
                        return done(null, user);
                    });
                }
            });
        }
    ));

    passport.use(new GoogleStrategy({
            clientID: oAuth.googleAuth.clientId,
            clientSecret: oAuth.googleAuth.clientSecret,
            callbackURL: oAuth.googleAuth.callbackUrl,
            passReqToCallback: true
        },
        function(req, accessToken, refreshToken, profile, done) {
            process.nextTick(function() {
                if(!req.user) {
                    User.findOne({'google.id': profile.id}, function(err, user) {
                        if(err) {
                            return done(err);
                        }
                        if(user) {
                            if(!user.token) {
                                user.token = accessToken;
                                user.save(function(err) {
                                    if(err) {
                                        throw err;
                                    }
                                });
                            }
                            return done(null, user);
                        } else {
                            var newUser = new User();
                            newUser.google.id = profile.id;
                            newUser.google.token = accessToken;
                            newUser.google.name = profile.displayName;
                            newUser.google.email = profile.emails[0].value;
                            newUser.google.photo = profile.photos[0].value.slice(0, profile.photos[0].value.length-2) + "400";
                            newUser.save(function(err) {
                                if(err) {
                                    throw err;
                                }
                                return done(null, newUser);
                            });
                        }
                    });
                } else {
                    var user = req.user;
                    user.google.id = profile.id;
                    user.google.token = accessToken;
                    user.google.name = profile.displayName;
                    user.google.email = profile.emails[0].value;
                    user.google.photo = profile.photos[0].value.slice(0, profile.photos[0].value.length-2) + "400";
                    user.save(function(err) {
                        if (err) {
                            throw err;
                        }
                        return done(null, user);
                    });
                }
            });
        }
    ));
};