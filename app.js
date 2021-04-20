//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require ('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static('public'));
app.use(session({
  secret: "wowseriouslydotenvdoesntworkhere???????????",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

mongoose.connect(process.env.mongoDbLink, {useNewUrlParser: true, useUnifiedTopology: true});
const userSchema = new mongoose.Schema({
  name: {type: String, required: false},
  username: {type: String},
  googleId: String,
  facebookId: String,
  secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model('User', userSchema);

const LocalStrategy = require('passport-local').Strategy;
passport.use(new LocalStrategy(User.authenticate()));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// passport.use(new GoogleStrategy({
//     clientID: process.env.googleClientId,
//     clientSecret: process.env.googleClientSecret,
//     callbackURL: process.env.googleCbURL
//   },
//   function(accessToken, refreshToken, profile, done) {
//         console.log(profile);
//        User.findOrCreate({ googleId: profile.id }, { username: profile.displayName}, function (err, user) {
//          return done(err, user);
//        });
//   }
// ));

passport.use(new FacebookStrategy({
    clientID: process.env.facebookClientId,
    clientSecret: process.env.facebookClientSecret,
    callbackURL: process.env.facebookCbURL
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/', (req, res) => {
  res.render('home', {});
});

app.route('/login')
  .get(function (req, res) {
    res.render('login', {});
  })
  .post(function (req, res, next) {
    passport.authenticate('local', function(err, user, info) {
   if (err) { return next(err); }
   if (!user) { return res.redirect('/login'); }
   req.logIn(user, function(err) {
     if (err) { return next(err); }
     return res.redirect('/secrets');
   });
 })(req, res, next);
  });

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/secrets', (req, res) => {
  if(req.isAuthenticated()){
        User.find( {secret: { $ne: null } }, (err, usersFound) => {
          if (err) {
            console.log(err);
          }else {
            res.render('secrets', {secretsList: usersFound});
          }
        });
    }
    else {
    res.redirect("/login");
  }
});

app.get('/submit', (req, res) => {
  if(req.isAuthenticated()){
        res.render('submit');
    }
    else {
    res.redirect("/login");
  }
});

app.post('/submit', (req, res) => {
  User.updateOne({_id: req.user._id}, {secret: req.body.secret}, (err, result) => {
    if (err) {
      console.log(err);
      res.redirect('/submit');
    }else {
      res.redirect('/secrets');
    }
  });
});

app.route('/register')
  .get(function (req, res) {
    res.render('register', {});
  })
  .post(function (req, res) {
    User.register({username:req.body.username, email: req.body.username}, req.body.password, function(err, user) {
      if (err)
      {
        console.log(err)
        res.redirect('/register');
      }else {
      passport.authenticate('local')(req, res, function () {
          res.redirect('/secrets');
      });
      }
    });
  });




  app.listen(process.env.PORT || 3000, function() {
    console.log('Server is listening on port 3k');
  });
