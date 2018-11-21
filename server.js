var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var morgan = require('morgan');
var fs = require('fs');
const jwt = require('jsonwebtoken');
const config = require('./config');
const chat_room = {}
const group_room = []

// invoke an instance of express application.
var app = express();

// set our application port
app.set('port', 9000);

// set morgan to log info about our requests for development use.
app.use(morgan('dev'));

// initialize body-parser to parse incoming parameters requests to req.body
app.use(bodyParser.urlencoded({ extended: true }));

// initialize cookie-parser to allow us access the cookies stored in the browser. 
app.use(cookieParser());
app.set('view engine', 'ejs')

// initialize express-session to allow us track the logged-in user across sessions.
app.use(session({
    key: 'user_sid',
    secret: 'somerandonstuffs',
    resave: false,
    saveUninitialized: false,
    cookie: {
        expires: 6000
    }
}));

// start the express server
const server = app.listen(app.get('port'), () => console.log(`App started on port ${app.get('port')}`));

const io = require('socket.io')(server)

io.on('connection', (socket) => {
    console.log("new user connected")

    socket.on('addChatSocket', function(username){
        chat_room[username] = socket.id
        var rawdata = fs.readFileSync('groupData.json');
        var groupData = JSON.parse(rawdata);
        console.log("chat_room ::: ")
        console.log(chat_room)
        socket.emit('all_loginUsers_userGroups', {chat_room: chat_room, group_room: groupData})
    })

    socket.on('new_message', function (data) {
        const sender = data.sender
        const receiver = data.reciever
        io.sockets.in(chat_room[receiver]).emit('new_message', { message: data.message, sender: sender })
    })

    socket.on('create_group', function (data) {
        const users = data.users
        const group_name = data.group_name
        var rawdata = fs.readFileSync('groupData.json');
        var groupData = JSON.parse(rawdata);
        groupData[group_name] = users
        for (var i = 0; i < users.length; i++) {
            io.sockets.in(chat_room[users[i]]).emit('new_group', { group_name: group_name })
        }
        fs.writeFileSync('groupData.json', JSON.stringify(groupData));
    })

    socket.on('new_group_message', function (data) {
        const sender = data.sender
        const group_name = data.group
        const message = data.message
        var rawdata = fs.readFileSync('groupData.json');
        var groupData = JSON.parse(rawdata);
        const group_users = groupData[group_name]
        for (var i = 0; i< group_users.length; i++) {
            if(group_users[i] != sender) {
                io.sockets.in(chat_room[group_users[i]]).emit('new_group_message', { message: message, group_name: group_name, sender: sender })
            }
        }
    })
});


function insertDataJson(data) {
    var rawdata = fs.readFileSync('userData.json');
    var userData = JSON.parse(rawdata);
    userData.push(data)
	fs.writeFileSync('userData.json', JSON.stringify(userData)); 
}

function checkUser (username, password, callback) {
    var rawdata = fs.readFileSync('userData.json');
    var userData = JSON.parse(rawdata);
    let checked = false
    for (var i = 0; i < userData.length; i++) {
        if (((userData[i].username == username) || (userData[i].email == username)) && (userData[i].password == password)) {
            checked = true
        }
    }
    callback(checked)
}


// This middleware will check if user's cookie is still saved in browser and user is not set, then automatically log the user out.
// This usually happens when you stop your express server after login, your cookie still remains saved in the browser.
app.use((req, res, next) => {
    if (req.cookies.user_sid && !req.session.user) {
        res.clearCookie('user_sid');        
    }
    next();
});

// middleware function to check for logged-in users
var sessionChecker = (req, res, next) => {
    const token = req.headers['x-access-token'] || req.body.token;
    console.log("token is ::: "+token)
    if (!token) return next();
    jwt.verify(token, config.secret, function(err, decoded) {
        if (err) return next();
        return res.redirect('/dashboard');
    });
};


// route for Home-Page
app.get('/', sessionChecker, (req, res) => {
    res.redirect('/login');
});

// route for user signup
app.route('/signup')
    .get(sessionChecker, (req, res) => {
        //res.sendFile(__dirname + '/public/signup.html');
        res.render('signup')
    })
    .post((req, res) => {
        insertDataJson({
            fullname: req.body.fullname,
            username: req.body.username,
            email: req.body.email,
            password: req.body.password
        })
        res.redirect('/login')
    });


// route for user Login
app.route('/login')
    .get(sessionChecker, (req, res) => {
        //res.sendFile(__dirname + '/public/login.html');
        res.render('login')
    })
    .post((req, res) => {

        var username = req.body.username,
            password = req.body.password;

            checkUser(username, password, function (matched) {
                if (! matched) {
                    console.log("username or password not matched.")
                    res.redirect('/login');
                } else {
                    const token = jwt.sign({
                            username: username 
                        }, 
                        config.secret, {
                            expiresIn: 86400 // expires in 24 hours
                        });
                    console.log("token 2 :: "+token)
                    req.session.username = username
                    res.json({token: token, username: username, redirect: '/dashboard'});
                }
            })
    });

// route for user's dashboard
app.route('/dashboard')
    .get(sessionChecker, (req, res) => {
        if (true) {
            const username = req.session.username
            res.render('dashboard', { username: username, loginUser: chat_room })
        } else {
            res.redirect('/login');
        }
    })
    .post(sessionChecker, (req, res) => {

    })


// route for user logout
app.get('/logout', (req, res) => {
    res.redirect('/login');
});


// route for handling 404 requests(unavailable routes)
app.use(function (req, res, next) {
  res.status(404).send("Sorry can't find that!")
});
