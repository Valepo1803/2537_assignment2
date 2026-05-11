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
app.set('view engine', 'ejs');

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
app.use((req, res, next) => {
    res.locals.currentURL = req.url;
    res.locals.navLinks = [
        { name: "Home", link: "/" },
        { name: "Members", link: "/members" },
        { name: "Login", link: "/login" },
        { name: "Admin", link: "/admin" },
        { name: "404", link: "/404" }
    ];
    next();
});

app.get("/", (req, res) => {
  res.render("index", { user: req.session.username || null });
});

app.get("/signout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get('/signup', (req, res) => {
    res.render("signup");
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
    await userCollection.insertOne({username, email, password: hashedPassword, user_type: 'user'});
    
    req.session.authenticated = true;
    req.session.username = username;
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/loggingin', async (req, res) => {
    let { email, password } = req.body;

    const user = await userCollection.findOne({ email: email });

    if (user && await bcrypt.compare(password, user.password)) {
        req.session.authenticated = true;
        req.session.username = user.username;
        req.session.user_type = user.user_type;
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
    res.render("members", { username: req.session.username });
});

app.get('/admin', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }
    if (req.session.user_type !== 'admin') {
        res.status(403);
        res.send("Error 403: You do not have permission to view this page. <a href='/'>Back to Home</a>");
        return;
    }

    const users = await userCollection.find().toArray();
    res.render("admin", { users: users });
});

app.post('/promote', async (req, res) => {
    const username = req.body.username;
    await userCollection.updateOne({ username: username }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
});

app.post('/demote', async (req, res) => {
    const username = req.body.username;
    await userCollection.updateOne({ username: username }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

app.use((req,res) => {
	res.status(404);
	res.render("404");
});

app.listen(PORT, () => {
  console.log("Node application listening on port" + PORT);
});