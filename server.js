const express = require('express');
const session = require('express-session');
const flash = require('express-flash');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();

mongoose.connect('mongodb://localhost/login_and_registration').catch(()=>{
  console.log('Make sure that Mongod is running!');
});

app.set('trust proxy', 1);
app.use(session({
  secret: "super secret",
  saveUninitialized: true,
  resave: false,
  cookie: { maxAge: 60000 }
}));

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

app.use(bodyParser.urlencoded({extended: true}));
app.use(flash());

const UserSchema = new mongoose.Schema({
    first_name: { type: String, 
                  required: [true, "First Name: is required."],
                  minlength: [3, "First Name: must include at least 3 characters."]
    },
    last_name:  { type: String, 
                  required: [true, "Last Name: is required."],
                  minlength: [2, "Last Name: must include at least 2 characters."]
    },
    email:      { type: String, 
                  required: [true, "Email: is required."], 
                  unique: [true, "Email is already taken!"],
                  validate: {
                    validator: (email)=>{
                      var emailRegex = /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/;
                      
                      return emailRegex.test(email);
                    },
                    message: '"{VALUE}" is not a valid email address.'
                  }
    },
    birth_date: { type: Date,
                  required: [true, "Birth Date: is required."]
    },
    password:   { type: String,
                  required: [true, "Password: is required."],
                  minlength: [7, "Password must include at least 7 characters."]
    },
  }, {timestamps: true}
);

mongoose.model("User", UserSchema);

const User = mongoose.model("User");

app.get('/', (req, res)=>{
  res.render('index', {'session': req.session});
});

app.post('/login', (req, res)=>{
  User.findOne({email: req.body.email}, (err, user)=>{
    if(err){
      console.log(err);
      req.flash("login_errors", "User credentials not found or invalid!");
      res.redirect('/');
    }
    
    if(user){
      console.log(user);

      bcrypt.compare(req.body.password, user.password)
        .then(result=>{
          console.log(result);

          req.session.user_id = user.id;
          req.session.name = user.first_name;
    
          res.render('profile', {'session': req.session});
        })
        .catch(error=>{
          console.log(error);
        
          req.flash("login_errors", "User credentials not found or invalid!");
          res.redirect('/');
        })
    }else{
      req.flash("login_errors", "User credentials not found or invalid!");
      res.redirect('/');
    }
  });
});

app.post('/registration', (req, res)=>{
  if(req.body.password === req.body.password_confirm){
    
    bcrypt.hash(req.body.password, 10, (err, hashed)=>{
      if(err){
        console.log(err);

        req.flash("registration_errors", "Error processing registration.");
        res.redirect('/');
      }else{
        let user = new User({
          first_name: req.body.first_name,
          last_name: req.body.last_name,
          email: req.body.email,
          birth_date: req.body.birth_date,
          password: hashed
        });

        user.save(err=>{
          if(err){
            
            for(var error in err.errors){
              console.log(err.errors[error].message);
              req.flash("registration_errors", err.errors[error].message);
            }
            res.redirect('/');
          }else{
            req.session.user_id = user.id;
            req.session.name = user.first_name;
    
            res.render('profile', {'session': req.session});
          }
        })
      }
    })
  }else{
    req.flash("registration_errors", "Passwords do not match!");
    res.redirect('/');
  }
});

app.get('/profile', (req, res)=>{
  if(req.session.user_id){
    console.log(req.session);
    res.render('profile', {'session': req.session})
  }else{
    console.log(req.session);
    console.log('session info missing');

    req.flash("login_errors", "Session timed out.")
    res.redirect('/');
  }
});

app.get('/logout', (req, res)=>{
  req.session.destroy();

  res.redirect('/');
});

app.listen(7777, function(){
  console.log("Express app listening on port 7777");
});