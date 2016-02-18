/**
 * Created by subham_1994 on १३-०२-२०१६.
 */
var express = require('express');
var morgan = require('morgan');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var mongoose = require('mongoose');
var bodyParser = require('body-parser');
var passport = require('passport');
var flash = require('connect-flash');
var mongoSessionStore = require('connect-mongo')(session);
var configDb = require('./config/database');
var app = express();
var PORT = process.env.PORT || 3000;

mongoose.connect(configDb.url);
require('./config/passport')(passport);

app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/static'));
app.use(bodyParser.urlencoded({extended: false}));
app.use(morgan('dev'));
app.use(cookieParser());
app.use(session({
    secret: "hardest secret to guess !!",
    saveUninitialized: true,
    resave: true,
    store: new mongoSessionStore({mongooseConnection: mongoose.connection})
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

require('./app/routes')(app, passport);

app.listen(PORT, function() {
    console.log('Express listening on port ' + PORT);
});
