const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// Фиктивный массив пользователей (в реальном приложении этот массив будет заменен базой данных)
const users = [
  { id: 1, username: 'user1', password: 'password1' },
  { id: 2, username: 'user2', password: 'password2' }
];

passport.use(new LocalStrategy(
  (username, password, done) => {
    // Поиск пользователя по имени пользователя
    const user = users.find(u => u.username === username);
    if (!user) {
      return done(null, false, { message: 'Неправильное имя пользователя' });
    }
    if (user.password !== password) {
      return done(null, false, { message: 'Неправильный пароль' });
    }
    return done(null, user);
  }
));
