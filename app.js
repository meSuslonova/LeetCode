const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const User = require('./models/user');
const Task = require('./models/task');
const Comment = require('./models/comment');
const Discussion = require('./models/discussion');
const flash = require('connect-flash');
const { check, validationResult } = require('express-validator');
const logger = require('./logger');
const csrf = require('csurf');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const uuid = require('uuid');
const multer = require('multer');
const router = express.Router();
const debugFileUploadMiddleware = require('./middlewares/debugFileUploadMiddleware');

const app = express();

// Функция для проверки аутентификации пользователя
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next(); // Продолжаем выполнение цепочки middleware
    }
    res.redirect('/login'); // Если пользователь не аутентифицирован, перенаправляем на страницу входа
};

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
            if (isMatch) { return done(null, user); }
            else { return done(null, false, { message: 'Неверный логин или пароль' }); }
        } catch (err) {
            return done(err);
        }
    }

));

// Настройка сериализации и десериализации пользователя
passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser(async (_id, done) => {
    try {
        const user = await User.findOne({ _id: _id });
        if (!user) {
            return done(null, false, { message: 'Пользователь не найден' });
        }
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Настройка приложения
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.static('public', { maxAge: 0 }));
app.use('/js', express.static('js', {
    setHeaders: (res, path) => {
        if (path.endsWith('.js')) {
            res.set('Content-Type', 'application/javascript');
        }
    }
}));
app.use(session({
    secret: 'your-secret-string',
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash()); // Инициализация пакета connect-flash
app.use((req, res, next) => {
    res.locals.isAuthenticated = req.isAuthenticated();
    next();
});

app.use((req, res, next) => {
    res.locals.error = req.flash('error');
    next();
});

app.use((req, res, next) => {
    res.locals.warning = req.flash('warning');
    next();
});

app.use((req, res, next) => {
    const csrfToken = req.csrfToken();
    res.locals.csrfToken = csrfToken;
    next();
});

app.use((err, req, res, next) => {
    if (err && err.code === 'EBADCSRFTOKEN') {
        // Обработка недействительного токена CSRF
        res.status(403).send('Invalid CSRF Token');
    } else {
        next(err); // Передача управления следующему middleware для обработки других ошибок
    }
});
app.use('/admin', router);

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Подключение к базе данных MongoDB
mongoose.connect('mongodb://localhost:27017/my_database', {})
    .then(() => console.log('Успешное подключение к MongoDB!'))
    .catch(err => console.error('Ошибка подключения к MongoDB:', err));

// Защищенная страница для отображения после входа пользователя
app.get('/dashboard', csrfProtection, isAuthenticated, (req, res) => {
    const csrfToken = req.csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken);
    res.redirect('/user/' + req.user._id);
});

// Обработка маршрутов
app.get('/', csrfProtection, (req, res) => {
    logger.info('Получен запрос на главную страницу');
    const csrfToken = req.csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken);
    res.render('app', { csrfToken: csrfToken, isAuthenticated: req.isAuthenticated(), activeTab: 'home' });
});

app.get('/about', csrfProtection, (req, res) => {
    const csrfToken = req.csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken);
    res.render('about', { csrfToken: csrfToken, isAuthenticated: req.isAuthenticated(), activeTab: 'about' });
});

app.get('/tasks', csrfProtection, isAuthenticated, async (req, res) => {
    try {
        const tasks = await Task.find({ $or: [{ username: req.user.username }, { visibility: 'public' }] });
        const csrfToken = req.csrfToken();
        res.locals.csrfToken = csrfToken;
        res.cookie('XSRF-TOKEN', csrfToken);
        res.render('tasks', { tasks: tasks, csrfToken: csrfToken, isAuthenticated: req.isAuthenticated(), user: req.user, activeTab: 'tasks' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});


app.get('/submit/:id', csrfProtection, isAuthenticated, async (req, res) => {
    try {
        const task = await Task.findOne({ _id: req.params.id });
        if (!task) {
            return res.status(404).send('Задача не найдена');
        }
        const comments = await Comment.find({ taskId: req.params.id, visibility: 'public' });

        const csrfToken = req.csrfToken();
        res.locals.csrfToken = csrfToken;
        res.cookie('XSRF-TOKEN', csrfToken);
        res.render('submit', { task: task, csrfToken: csrfToken, isAuthenticated: req.isAuthenticated(), comments: comments, activeTab: 'tasks' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.get('/discuss/:id', csrfProtection, isAuthenticated, async (req, res) => {
    try {
        const task = await Task.findOne({ _id: req.params.id });
        if (!task) {
            return res.status(404).send('Задача не найдена');
        }
        const discussions = await Discussion.find({ taskId: req.params.id, visibility: 'public' });

        const csrfToken = req.csrfToken();
        res.locals.csrfToken = csrfToken;
        res.cookie('XSRF-TOKEN', csrfToken);
        res.render('discuss', { task: task, csrfToken: csrfToken, isAuthenticated: req.isAuthenticated(), discussions: discussions, activeTab: 'tasks' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.get('/createTask', csrfProtection, isAuthenticated, (req, res) => {
    const csrfToken = req.csrfToken();// Generate CSRF token
    res.locals.csrfToken = csrfToken;
    res.cookie('XSRF-TOKEN', csrfToken);
    res.render('createTask', { csrfToken: csrfToken, isAuthenticated: req.isAuthenticated(), activeTab: 'tasks' });
});

app.get('/editTask/:id', csrfProtection, isAuthenticated, async (req, res) => {
    try {
        const task = await Task.findOne({ _id: req.params.id, username: req.user.username });
        if (!task) {
            return res.status(404).send('Задача не найдена');
        }
        const csrfToken = req.csrfToken();
        res.locals.csrfToken = csrfToken;
        res.cookie('XSRF-TOKEN', csrfToken);
        res.render('editTask', { task: task, csrfToken: csrfToken, isAuthenticated: req.isAuthenticated(), activeTab: 'tasks' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.get('/deleteTask/:id', csrfProtection, async (req, res) => {
    try {
        const task = await Task.findOne({ _id: req.params.id, username: req.user.username });
        if (!task) {
            return res.status(404).send('Задача не найдена');
        }
        if (!req.user || req.user.role !== 'admin') {
            return res.status(401).send('Необходимо войти в систему как администратор');
        }

        await Task.deleteOne({ _id: req.params.id, username: req.user.username });
        res.redirect('/tasks');
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.get('/registration', csrfProtection, (req, res) => {
    const csrfToken = req.csrfToken(); // Генерация CSRF токена
    const messages = req.flash('error'); // Получение сообщения об ошибках
    res.cookie('XSRF-TOKEN', csrfToken);
    res.render('registration', {
        csrfToken: csrfToken,
        messages: messages,
        activeTab: 'registration'
    });
});

app.get('/settings/password', csrfProtection, (req, res) => {
    const csrfToken = req.csrfToken(); // Генерация CSRF токена
    const messages = req.flash('error'); // Получение сообщения об ошибках
    res.cookie('XSRF-TOKEN', csrfToken);
    res.render('settings/password', {
        csrfToken: csrfToken,
        messages: messages,
        activeTab: 'dashboard'
    });
});

app.get('/login', csrfProtection, (req, res) => {
    if (req.isAuthenticated()) { res.redirect(`/user/${req.user.username}`); } else {
        const messages = req.flash('error'); // Получаем сообщения об ошибках из сессии
        const csrfToken = req.csrfToken();
        res.locals.csrfToken = csrfToken;
        res.cookie('XSRF-TOKEN', csrfToken); // Устанавливаем куку с именем 'XSRF-TOKEN' 
        res.render('login', { csrfToken: csrfToken, messages: messages, activeTab: 'login' }); // Передаем сообщения об ошибках в шаблон
    }
});

app.get('/user/:userId', csrfProtection, async (req, res) => {
    const csrfToken = req.csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken);
    if (!mongoose.Types.ObjectId.isValid(req.params.userId)) {
        return res.status(400).send('Неверный идентификатор пользователя');
    }
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            console.error(`Пользователь с идентификатором ${req.params.userId} не найден`);
            return res.status(404).send('Пользователь не найден');
        }
        const users = await User.find();
        const tasksWithComments = await Comment.aggregate([
            { $match: { username: user.username } }, // Найти комментарии пользователя
            { $group: { _id: "$taskId" } } // Сгруппировать комментарии по задачам
        ]);
        const taskIds = tasksWithComments.map(task => task._id);
        const tasks = await Task.find({ _id: { $in: taskIds } }); // Загрузить задачи
        const discussions = user.discussions ? Object.values(user.discussions) : [];
        const averageRating = user.ratings.length > 0 ? user.ratings.reduce((acc, curr) => acc + curr, 0) / user.ratings.length : 0;
        res.render('user', {
            csrfToken: csrfToken,
            username: user.username,
            user: req.user,
            users: users,
            email: user.email,
            role: user.role,
            tasks: tasks, // Передать загруженные задачи
            discussions: discussions,
            averageRating: averageRating,
            rating: user.rating, // Индивидуальный рейтинг пользователя
            activeTab: 'dashboard',
            comments: tasksWithComments
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});


app.get('/admin/user/:userId', csrfProtection, isAuthenticated, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).send('Доступ запрещен');
        }

        const csrfToken = req.csrfToken();
        res.cookie('XSRF-TOKEN', csrfToken);

        const userId = req.params.userId;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('Пользователь не найден');
        }
        if (user.ratings.length > 0) {
            const sumOfRatings = user.ratings.reduce((acc, curr) => acc + curr, 0);
            user.rating = sumOfRatings / user.ratings.length;
        } else {
            user.rating = 0; // Установка рейтинга в 0, если массив оценок пуст
        }
        const users = await User.find();
        const tasksWithComments = await Comment.aggregate([
            { $match: { username: user.username } }, // Найти комментарии пользователя
            { $group: { _id: "$taskId" } } // Сгруппировать комментарии по задачам
        ]);
        const taskIds = tasksWithComments.map(task => task._id);
        const tasks = await Task.find({ _id: { $in: taskIds } }); // Загрузить задачи
        const discussions = user.discussions ? Object.values(user.discussions) : [];
        res.render('admin/user', {
            csrfToken: csrfToken,
            username: user.username,
            user: user,
            users: users,
            email: user.email,
            role: user.role,
            tasks: tasks,
            discussions: discussions,
            averageRating: user.rating,
            rating: user.rating, // Индивидуальный рейтинг пользователя
            activeTab: 'dashboard',
            comments: tasksWithComments
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});


app.get('/admin/users', csrfProtection, async (req, res) => {
    const csrfToken = req.csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken);

    try {
        const users = await User.find(); // Получить всех пользователей из базы данных

        res.render('admin/users', {
            csrfToken: csrfToken,
            users: users, // Передать список пользователей в представление
            user: req.user,
            email: req.user,
            username: req.user,
            role:req.user,
            activeTab: 'dashboard' // Передать текущего пользователя в представление (если он есть)
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});


app.get('/secure-route', isAuthenticated, (req, res) => {
    // Логика для защищенного маршрута
    res.send('Вы успешно аутентифицированы и имеете доступ к защищенному маршруту.');
});

app.get('/xsrf-token', csrfProtection, (req, res) => {
    const csrfToken = req.csrfToken();
    res.json({ csrfToken });
});

app.post('/set-role', csrfProtection, isAuthenticated, async (req, res) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN']; // Получаем токен CSRF из куки
    if (csrfToken !== cookieToken) {
        return res.status(403).send('Неверный токен CSRF');
    }

    if (!req.user || req.user.role !== 'admin') {
        return res.status(401).send('Необходимо войти в систему как администратор');
    }

    const { userId, role } = req.body;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).send('Неверный идентификатор пользователя');
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('Пользователь не найден');
        }

        if (user.role === 'admin' && role === 'user') {
            return res.status(400).send('Нельзя понизить роль администратора до пользователя');
        }

        user.role = role;
        await user.save();
        res.redirect('/users');
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

// Обработка входа пользователя
app.post('/login', csrfProtection, (req, res, next) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN']; // Получаем токен CSRF из куки
    if (csrfToken !== cookieToken) {
        return res.status(403).send('Неверный токен CSRF');
    }
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            logger.error(`Ошибка аутентификации: ${err}`);
            return next(new Error('Ошибка аутентификации'));
        }

        if (!user) {
            const errorMessage = req.session.errorMessage || 'Неверные учетные данные';
            logger.warn(`Неудачная попытка входа: ${errorMessage}`);
            req.flash('error', errorMessage);
            return res.render('login', { csrfToken: csrfToken, messages: [errorMessage], activeTab: 'login' });
        }

        req.logIn(user, (err) => {
            if (err) {
                logger.error(`Ошибка входа пользователя: ${err}`);
                return next(new Error('Ошибка входа пользователя'));
            }
            logger.info(`Пользователь ${user.username} успешно вошел в систему`);
            const csrfToken = req.csrfToken();
            res.cookie('XSRF-TOKEN', csrfToken);
            return res.redirect('/dashboard');
        });
    })(req, res, next);
});

// Обработка регистрации пользователя
app.post('/register', csrfProtection, [check('username').notEmpty().isAlphanumeric(), check('email').isEmail(), check('password').isLength({ min: 6 })], async (req, res) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN']; // Получаем токен CSRF из куки
    if (csrfToken !== cookieToken) {
        return res.status(403).send('Неверный токен CSRF');
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMessage = req.session.errorMessage || 'Пожалуйста, заполните все поля формы';
        req.flash('error', errorMessage);
        return res.render('registration', { csrfToken: csrfToken, messages: [errorMessage], activeTab: 'register' });
    }
    if (!req.body.username || !req.body.email || !req.body.password) {
        const errorMessage = req.session.errorMessage || 'Пожалуйста, заполните все поля формы';
        req.flash('error', errorMessage);
        return res.redirect('/registration');
    }
    const { username, email, password } = req.body;
    const userId = uuid.v4(); // Генерация уникального ID

    // Проверка на существование пользователя
    const existingUser = await User.findOne({ username: username });
    if (existingUser) {
        const errorMessage = req.session.errorMessage || 'Пользователь с таким именем пользователя уже существует';
        req.flash('error', errorMessage);
        return res.render('registration', { csrfToken: csrfToken, messages: [errorMessage], activeTab: 'register' });
    }
    const existingEmail = await User.findOne({ email: email });
    if (existingEmail) {
        const errorMessage = req.session.errorMessage || 'Пользователь с таким адресом электронной почты уже существует';
        req.flash('error', errorMessage);
        return res.render('registration', { csrfToken: csrfToken, messages: [errorMessage], activeTab: 'register' });
    }

    const newUser = new User({ userId: uuid.v4(), username, email, password });
    try {
        await newUser.save();
        req.logIn(newUser, (err) => {
            if (err) {
                logger.error(`Ошибка входа пользователя: ${err}`);
                return next(new Error('Ошибка входа пользователя'));
            }

            logger.info(`Пользователь ${newUser.username} успешно вошел в систему`);
            res.cookie('XSRF-TOKEN', csrfToken); // Устанавливаем куки до перенаправления
            return res.redirect('/dashboard');
        });
    } catch (err) {
        if (err.name === 'ValidationError') {
            const messages = req.flash('error');
            const formData = { username: req.body.username, email: req.body.email }; // Сохранение введенных данных
            res.cookie('XSRF-TOKEN', csrfToken);
            res.render('registration', { csrfToken: csrfToken, _csrf: csrfToken, messages: messages, formData: formData, activeTab: 'register' });
        } else {
            console.error(err);
            req.flash('error', 'Ошибка при регистрации пользователя');
            const messages = req.flash('error');
            const formData = { username: req.body.username, email: req.body.email };
            res.cookie('XSRF-TOKEN', csrfToken);
            res.render('registration', { csrfToken: csrfToken, _csrf: csrfToken, messages: messages, formData: formData, activeTab: 'register' });
        }
    }
});

app.post('/settings/password', csrfProtection, [
    check('currentPassword').notEmpty(),
    check('newPassword').isLength({ min: 6 }),
    check('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.newPassword) {
            throw new Error('Пароли не совпадают');
        }
        return true;
    }),
], async (req, res) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN']; // Получаем токен CSRF из куки
    if (csrfToken !== cookieToken) {
        return res.status(403).send('Неверный токен CSRF');
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMessage = req.session.errorMessage || 'Пожалуйста, заполните все поля формы';
        req.flash('error', errorMessage);
        return res.render('settings/password', { csrfToken: csrfToken, messages: [errorMessage], activeTab: 'dashboard' });
    }
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id); // Получаем пользователя из базы данных
    if (!user) {
        return res.status(404).send('Пользователь не найден');
    }
    const isPasswordCorrect = await user.comparePassword(currentPassword); // Сравнение введенного пароля с паролем в базе данных
    if (!isPasswordCorrect) {
        const errorMessage = req.session.errorMessage || 'Неверный текущий пароль';
        req.flash('error', errorMessage);
        return res.render('settings/password', { csrfToken: csrfToken, messages: [errorMessage], activeTab: 'dashboard' });
    }
    user.password = newPassword; // Установка нового пароля
    await user.save(); // Сохранение изменений в базе данных
    req.logIn(user, (err) => {
        if (err) {
            logger.error(`Ошибка входа пользователя: ${err}`);
            return next(new Error('Ошибка входа пользователя'));
        }
        logger.info(`Пользователь ${user.username} успешно вошел в систему`);
        const errorMessage = req.session.errorMessage || 'Пароль успешно изменен';
        req.flash('error', errorMessage);
        res.cookie('XSRF-TOKEN', csrfToken); // Устанавливаем куки до перенаправления
        return res.render('settings/password', { csrfToken: csrfToken, messages: [errorMessage],activeTab: 'dashboard' });
    });
});

app.post('/check-user', (req, res, next) => {
    let username = req.body.username;
    if (!username || username === "") {
        return next(new Error('Имя пользователя не указано')); // Передача ошибки в функцию next
    } else {
        return res.redirect(`/user/${username}`).locals({ _csrf: req.csrfToken() });
    }
});

app.post('/logout', csrfProtection, (req, res) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN'];
    if (csrfToken !== cookieToken) {
        return res.status(403).send('Invalid CSRF token');
    }
    req.logout((err) => {
        if (err) {
            console.error(err);
        }

        req.session.destroy((err) => {
            if (err) {
                console.error(err);
            }
            res.clearCookie('XSRF-TOKEN');
            res.redirect('/login');
        });
    });
});

router.get('/tasks', csrfProtection, async function (req, res) {
    try {
        const tasks = await Task.find();
        if (tasks.length === 0) {
            return res.render('tasks', { csrfToken: req.csrfToken(), tasks: [] });
        }
        const csrfToken = req.csrfToken();
        res.cookie('XSRF-TOKEN', csrfToken);
        res.render('tasks', { csrfToken: csrfToken, tasks: tasks });
    } catch (err) {
        console.log(err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/deleteTask/:id', csrfProtection, async (req, res) => {
    try {
        const task = await Task.findOne({ _id: req.params.id });
        if (!task) {
            return res.status(404).send('Задача не найдена');
        }
        if (!req.user || req.user.role !== 'admin') {
            return res.status(401).send('Необходимо войти в систему как администратор');
        }

        await Task.deleteOne({ _id: req.params.id });
        res.redirect('/tasks');
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.post('/createTask', csrfProtection, [
    check('description').notEmpty(),
    check('difficulty').notEmpty(),
    check('tags').notEmpty()
], debugFileUploadMiddleware, upload.array('files', 5), async (req, res) => {
    console.log('Reached this point');
    console.log('Uploaded files:', req.files);
    const cookieToken = req.cookies['XSRF-TOKEN'];
    const csrfToken = req.body._csrf;
    console.log(csrfToken);
    console.log(cookieToken);
    if (csrfToken !== cookieToken) {
        return res.status(403).send('Неверный токен CSRF');
    }
    // const errors = validationResult(req);
    // if (!errors.isEmpty()) {
    //     return res.status(422).json({ errors: errors.array() });
    // }
    if (!req.user || req.user.role !== 'admin') {
        const errorMessage = req.session.errorMessage || 'Необходимо войти в систему как администратор';
        req.flash('error', errorMessage);
        return res.render('createTask', { csrfToken: csrfToken, messages: [errorMessage] });
    }

    try {
        const files = req.files || []; // Если req.files не определено, установите пустой массив
        const filenames = files.map(file => file.filename);
        const links = req.body.links.split(',').map(link => {
            const [title,url ] = link.split('-'); // Assuming links are in the format "title-url"
            return { title,url };
        });

        const task = new Task({
            username: req.user.username,
            title: req.body.title,
            description: req.body.description,
            difficulty: req.body.difficulty,
            tags: req.body.tags.split(','),
            files: filenames,
            links: links,
            public: true
        });
        await task.save();
        logger.info(`Задача успешно создана`);
        res.cookie('XSRF-TOKEN', csrfToken);
        return res.redirect('/tasks');
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.post('/editTask/:id', csrfProtection, [
    check('description').notEmpty(),
    check('difficulty').notEmpty(),
    check('tags').notEmpty()
], upload.array('files', 5), async (req, res) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN']; // Получаем токен CSRF из куки

    if (csrfToken !== cookieToken) {
        return res.status(403).send('Неверный токен CSRF');
    }
    // const errors = validationResult(req);
    // if (!errors.isEmpty()) {
    //     return res.status(400).json({ errors: errors.array() });
    // }
    if (!req.user || req.user.role !== 'admin') {
        return res.status(401).send('Необходимо войти в систему как администратор');
    }

    try {
        const task = await Task.findOne({ _id: req.params.id, username: req.user.username });
        if (!task) {
            return res.status(404).send('Задача не найдена');
        }
        if (!req.user || req.user.role !== 'admin') {
            return res.status(401).send('Необходимо войти в систему как администратор');
        }
        const previousTitle = task.title;
        const previousDescription = task.description;
        const previousDifficulty = task.difficulty;
        const previousTags = task.tags;
        const previousFiles = task.files;
        const previousLinks = task.links;

        task.title = req.body.title || previousTitle;
        task.description = req.body.description || previousDescription;
        task.difficulty = req.body.difficulty || previousDifficulty;
        task.tags = req.body.tags ? req.body.tags.split(',') : previousTags;

        const files = req.files || []; // Если req.files не определено, установите пустой массив
        const filenames = files.map(file => file.filename);
        task.files = filenames.length > 0 ? filenames : previousFiles;
        task.files = filenames;
        const links = req.body.links ? req.body.links.split(',').map(link => {
            const [url, title] = link.split('|'); // Предполагая, что ссылки в формате "url|title"
            return { url, title };
        }) : previousLinks;
        task.links = links.length > 0 ? links : previousLinks;

        await task.save();
        res.redirect('/tasks');
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.post('/deleteComment/:id', isAuthenticated, async (req, res) => {
    try {
        const comment = await Comment.findOne({ _id: req.params.id, username: req.user.username });
        if (!comment) {
            return res.status(404).send('Комментарий не найден');
        }

        await Comment.deleteOne({ _id: req.params.id });
        res.redirect('/submit/' + comment.taskId); // Перенаправляем обратно на страницу с задачей

    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.post('/deleteDiscuss/:id', isAuthenticated, async (req, res) => {
    try {
        const discussion = await Discussion.findOne({ _id: req.params.id, username: req.user.username });
        if (!discussion) {
            return res.status(404).send('Комментарий не найден');
        }

        await Discussion.deleteOne({ _id: req.params.id });
        res.redirect('/discuss/' + discussion.taskId); // Перенаправляем обратно на страницу с задачей

    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});


app.post('/admin/user/:userId/rate', csrfProtection, isAuthenticated, async (req, res) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN']; // Получаем токен CSRF из куки

    if (csrfToken !== cookieToken) {
        return res.status(403).send('Неверный токен CSRF');
    }
    if (req.user.role !== 'admin') {
        return res.status(403).send('Доступ запрещен');
    }

    try {
        const userId = req.params.userId;
        const { rating } = req.body;
        if (!rating.trim()) {
            return res.status(400).send('Рейтинг не может быть пустым');
        }
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('Пользователь не найден');
        }
        user.ratings.push(parseInt(rating));
        user.rating = user.ratings.reduce((acc, curr) => acc + curr, 0) / user.ratings.length;

        await user.save();
        res.redirect(`/admin/user/${userId}`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.post('/submit/:id', async (req, res, next) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN']; // Get CSRF token from cookie

    if (csrfToken !== cookieToken) {
        return res.status(403).send('Invalid CSRF token');
    }

    try {
        const task = await Task.findOne({ _id: req.params.id });
        if (!task) {
            return res.status(404).send('Task not found');
        }

        const newCommentData  = await Comment.create({
            username: req.user.username,
            content: req.body.content,
            taskId: req.params.id,
            public: true,
            createdAt: req.body.createdAt || new Date()
        });

        const comment = await Comment.create(newCommentData);
        const comments = await Comment.find({ taskId: req.params.id, visibility: 'public' })
        .sort({ createdAt: 'desc' });

        // Check if task is defined before rendering the template
        if (task) {
            res.render('submit', {
                task: task,
                csrfToken: csrfToken,
                isAuthenticated: req.isAuthenticated(),
                comments: comments,
                activeTab: 'tasks'
            });
        } else {
            // Handle the case where task is undefined
            return res.status(404).send('Task not found');
        }
    } catch (err) {
        next(err);
    }
});

app.post('/discuss/:id', async (req, res, next) => {
    const csrfToken = req.body._csrf;
    const cookieToken = req.cookies['XSRF-TOKEN']; // Получаем токен CSRF из куки

    if (csrfToken !== cookieToken) {
        return res.status(403).send('Неверный токен CSRF');
    }
    try {
        const task = await Task.findOne({ _id: req.params.id });
        if (!task) {
            return res.status(404).send('Задача не найдена');
        }
        const discussion = await Discussion.create({
            username: req.user.username,
            content: req.body.content,
            taskId: req.params.id,
            public: true,
            createdAt: new Date()
        });
        const discussions = await Discussion.find({ taskId: req.params.id, visibility: 'public' })
        .sort({ createdAt: 'desc' });
        res.render('discuss', { task: task, csrfToken: csrfToken, isAuthenticated: req.isAuthenticated(), discussions: discussions, activeTab: 'tasks' });
    } catch (err) {
        next(err);
    }
});

router.get('/login',csrfProtection, (req, res) => {
    const errorMessage = req.session.errorMessage;
    req.session.errorMessage = 'Пользователь не найден';
    const csrfToken = req.csrfToken();
    res.cookie('XSRF-TOKEN', csrfToken);
    res.render('/login', { csrfToken: csrfToken, errorMessage: errorMessage });
});

// Добавление маршрута для отображения всех страниц пользователей
router.get('/admin/users',csrfProtection, isAuthenticated, async (req, res) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(401).send('Необходимо войти в систему как администратор');
    }

    try {
        const users = await User.find();
        if (users.length === 0) {
            return res.render('users', { csrfToken: req.csrfToken(), users: [] });
        }
        const csrfToken = req.csrfToken();
        res.cookie('XSRF-TOKEN', csrfToken);
        res.render('users', { csrfToken: csrfToken, users: users });
    } catch (err) {
        console.log(err);
        res.status(500).send('Internal Server Error');
    }
});

// Запуск сервера
const PORT = 4000;
const HOST = 'localhost';

app.listen(PORT, () => {
    console.log(`Server started: http://${HOST}:${PORT}`);
});
