/**
 * Created by subham_1994 on १३-०२-२०१६.
 */

(function() {
    var User = require('./models/user');

    var isLoggedIn = function(req, res, next) {
        if(req.isAuthenticated()) {
            return next();
        }
        res.redirect('/login');
    };

    module.exports = function(app, passport) {

        app.get('/', function(req, res) {
            res.render('index.ejs');
        });

        app.get('/login', function(req, res){
            res.render('login.ejs', { message: req.flash('loginMessage') });
        });

        app.post('/login', passport.authenticate('local-login', {
            successRedirect: '/profile',
            failureRedirect: '/login',
            failureFlash: true
        }));

        app.get('/signup', function(req, res){
            res.render('signup.ejs', { message: req.flash('signupMessage') });
        });

        app.get('/profile', isLoggedIn, function(req, res) {
            res.render('profile.ejs', { user: req.user });
        });

        app.post('/signup', passport.authenticate('local-signup', {
            successRedirect: '/profile',
            failureRedirect: '/signup',
            failureFlash: true
        }));

        app.get('/logout', function(req, res) {
            req.logout();
            res.redirect('/');
        });

        app.get('/auth/facebook', passport.authenticate('facebook', {scope: ['email']}));

        app.get('/auth/facebook/callback', passport.authenticate('facebook', {
            successRedirect: '/profile',
            failureRedirect: '/'
        }));

        app.get('/connect/local', function(req, res) {
            res.render('connect-local.ejs', { message: req.flash('loginMessage') });
        });
        app.post('/connect/local', passport.authenticate('local-signup', {
            successRedirect : '/profile',
            failureRedirect : '/connect/local',
            failureFlash : true
        }));

        app.get('/auth/google', passport.authenticate('google', {scope: ['profile', 'email']}));

        app.get('/auth/google/callback', passport.authenticate('google', {
            successRedirect: '/profile',
            failureRedirect: '/'
        }));

        app.get('/connect/facebook', passport.authorize('facebook', { scope: ['email'] }));

        app.get('/connect/facebook/callback', passport.authorize('facebook', {
            successRedirect : '/profile',
            failureRedirect : '/'
        }));

        app.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email'] }));

        app.get('/connect/google/callback', passport.authorize('google', {
            successRedirect : '/profile',
            failureRedirect : '/'
        }));
    };
}());