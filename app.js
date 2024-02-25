const express = require('express')
const { EvalSourceMapDevToolPlugin } = require('webpack')
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const app = express()

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(express.static('public'))
app.use('/js', express.static('js', {
    setHeaders: (res, path) => {
        if (path.endsWith('.js')) {
            res.set('Content-Type', 'application/javascript');
        }
    }
}));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


// Защищенная страница для отображения после входа пользователя
app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        res.send('Добро пожаловать, ' + req.user.username + '!');
    } else {
        res.redirect('/login');
    }
});


app.get('/', (req, res) => {
    res.render('app')
})

app.get('/about', (req, res) => {
    res.render('about')
})

app.get('/registration', (req, res) => {
    res.render('registration')
})

app.get('/user/:username', (req, res) => {
    let data = { username: req.params.username, hobbies: ['Football', 'Skate', 'Basketball'] }
    res.render('user', data);
})

// Обработчик маршрута для входа пользователя
app.post('/login', passport.authenticate('local', {
    successRedirect: '/user/dashboard',
    failureRedirect: '/login',
    failureFlash: true
}));

// Обработчик маршрута для регистрации пользователя
app.post('/register', async (req, res, next) => {
    const User = require('./models/user');
    const newUser = {
        username: req.body.username,
        email: req.body.email, // Убедитесь, что поле email присутствует в вашем запросе
        password: req.body.password
    };
    try {
        const user = new User(newUser);
        await user.save();
        res.redirect('/user/' + newUser.username);
    } catch (err) {
        next(err);
    }
});

app.post('/check-user', (req, res) => {
    let username = req.body.username
    if (username == "")
        return res.redirect('/')
    else
        return res.redirect('/user/' + username)
})

const PORT = 3000
const HOST = 'localhost'

app.listen(3000, () => {
    console.log(`Server started: http://${HOST}:${PORT}`)
})