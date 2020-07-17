require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const flash = require('express-flash-messages');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.use(express.static('public'));
app.set('view-engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(flash());
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Creating database connection
mongoose.connect("mongodb://localhost:27017/userDB", {
  useUnifiedTopology: true,
  useNewUrlParser: true
});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Passing information when user render the root directory.
app.get("/", function(req, res) {
  res.render("home.ejs");
});

app.get("/auth/google",
  passport.authenticate("google", { scope : ['profile'] })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

  app.get('/auth/facebook',
    passport.authenticate('facebook', { scope : ['public_profile'] })
  );

  app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect secrets.
      res.redirect('/secrets');
    });

app.get("/login", function(req, res) {
  res.render("login.ejs");
});

app.get("/register", function(req, res) {
  res.render("register.ejs");
});

app.get("/secrets", function(req,res){
  User.find({"secret" : {$ne : null}}, function(err,founduser){
    if(err){
      console.log(err);
    }else{
      if(founduser){
        res.render("secrets.ejs",{userWithSecrets : founduser});
      }
    }
  });

});

app.get("/submit",function(req, res){
  if(req.isAuthenticated()){
    res.render("submit.ejs");
  }else{
    res.redirect("/login");
  }
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.post("/submit",function(req, res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, founduser){
    if(err){
      console.log(err);
    }else{
      if(founduser){
        founduser.secret = submittedSecret;
        founduser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/register",function(req,res){
  User.register({username : req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      req.flash("notify","You are already registered.");
      res.redirect("/login");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  })
});


app.post("/login",function(req,res){
  const user = new User({
    username : req.body.username,
    password : req.body.password
  });

  req.login(user,function(err){
    if(err){
        console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});


app.listen(3000, function() {
  console.log("Server running on port 3000!!");
});
