require("dotenv").config();
// Fix for SRV DNS resolution issues on some networks (e.g. TELUS)
require("dns").setServers(["8.8.8.8"]);
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const app = express();
const Joi = require("joi");
let PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = require("./databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

let mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(
  session({
    secret: node_session_secret,
    resave: false,
    store: mongoStore,
    saveUninitialized: true,
  }),
);

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    let html = `<a href='/signup'><button>Sign up</button></a><br>
        <a href='/login'><button>Log in</button></a>`;
    res.send(html);
  } else {
    let html = `Hello, ${req.session.username}!<br>
        <a href='/members'><button>Go to Members Area</button></a><br>
        <a href='/signout'><button>Sign out</button></a>`;
    res.send(html);
  }
});

app.get("/signout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get('/signup', (req, res) => {
    res.send(`
        <form action='/signupSubmit' method='post'>
            <input name='username' type='text' placeholder='username'><br>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
});

app.post('/signupSubmit', async (req, res) => {
    let {username, email, password} = req.body;
    
    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({username, email, password});
    if (validationResult.error) {
        res.send(`${validationResult.error.details[0].message}. <a href='/signup'>Try again.</a>`);
        return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await userCollection.insertOne({username, email, password: hashedPassword});
    
    req.session.authenticated = true;
    req.session.username = username;
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.send(`
        <h2>Log In</h2>
        <form action='/loggingin' method='post'>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
});

app.post('/loggingin', async (req, res) => {
    let { email, password } = req.body;

    const user = await userCollection.findOne({ email: email });

    if (user && await bcrypt.compare(password, user.password)) {
        req.session.authenticated = true;
        req.session.username = user.username;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    } else {
        res.send("Invalid email/password combination. <a href='/login'>Try again</a>");
    }
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const images = ['cat-1.jpg', 'cat-2.jpg', 'cat-3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Hello, ${req.session.username}!</h1>
        <img src='/${randomImage}' style='width:300px;'><br>
        <a href='/signout'><button>Sign out</button></a>
    `);
});

app.use(express.static(__dirname + "/public"));

app.use((req,res) => {
	res.status(404);
	res.send("Page not found - 404");
});

app.listen(PORT, () => {
  console.log("Node application listening on port" + PORT);
});