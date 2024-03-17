const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');
const User = require('./models/user');
const flash = require('connect-flash');

const app = express();

// Настройка Passport для аутентификации
passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
},
    async (username, password, done) => {
        // Логика аутентификации
        try {
            const user = await User.findOne({ username: username });
            if (!user) { return done(null, false, { message: 'Неверный логин или пароль' }); }
            const isMatch = await user.comparePassword(password);
            if (isMatch) { return done(null, user); } // Добавлено done(null, user)
            else { return done(null, false, { message: 'Неверный логин или пароль' }); }
        } catch (err) {
            return done(err);
        }
    }

));

// Настройка сериализации и десериализации пользователя
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Настройка приложения
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use('/js', express.static('js', {
    setHeaders: (res, path) => {
        if (path.endsWith('.js')) {
            res.set('Content-Type', 'application/javascript');
        }
    }
}));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash()); // Инициализация пакета connect-flash
app.use((req, res, next) => {
    res.locals.isAuthenticated = req.isAuthenticated();
    next();
});

// Подключение к базе данных MongoDB
mongoose.connect('mongodb://localhost:27017/my_database', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Connected!'));

// Защищенная страница для отображения после входа пользователя
app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/user/' + req.user.username);
    } else {
        res.redirect('/login');
    }
});

// Обработка маршрутов
app.get('/', (req, res) => {
    res.render('app');
});

app.get('/about', (req, res) => {
    res.render('about');
});

app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect(`/user/${req.user.username}`);
    } else {
        res.render('registration'); // Отображение страницы входа в систему
    }
});

app.get('/registration', (req, res) => {
    res.render('registration');
});

app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

app.get('/user/:username', async (req, res) => {
    const user = await User.findById(req.params.username);
    res.render('user', { user: user ? user : null });
});

// Обработка входа пользователя
app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
}));
// Обработка регистрации пользователя
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const newUser = new User({ username, email, password });
    await newUser.save();
    res.redirect('/user/' + req.user.username);    // Перенаправление на страницу пользователя после успешной регистрации
});

app.post('/check-user', (req, res) => {
    let username = req.body.username;
    if (username === "") {
        return res.redirect('/');
    } else {
        return res.redirect(`/user/${username}`);
    }
});

// Запуск сервера
const PORT = 3000;
const HOST = 'localhost';

app.listen(PORT, () => {
    console.log(`Server started: http://${HOST}:${PORT}`);
});
