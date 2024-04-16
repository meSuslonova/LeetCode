# LeetCode

Клон LeetCode 
Описание программы AlgoMaster

Назначение:

Данная программа представляет собой полнофункциональное веб-приложение, которое позволяет пользователям управлять задачами, отправлять комментарии и взаимодействовать друг с другом.

Функциональные возможности:

Регистрация и вход: Пользователи могут зарегистрироваться и войти в систему, используя свою учетную запись.
Управление задачами: Пользователи могут создавать, редактировать и удалять задачи, а также просматривать список всех задач.
Отправка комментариев: Пользователи могут отправлять комментарии к задачам, а также просматривать комментарии других пользователей.
Поиск пользователей: Пользователи могут искать других пользователей по их имени пользователя и просматривать их профиль.
Управление пользователями: Администраторы могут управлять пользователями, включая изменение их ролей и удаление их учетных записей.
Защита от CSRF: Приложение защищено от атак с подделкой межсайтовых запросов (CSRF) с помощью токенов CSRF.
Обработка ошибок: Приложение обрабатывает ошибки и отображает соответствующие сообщения об ошибках пользователям.
Аутентификация: Приложение использует Passport.js для аутентификации пользователей.
Хранение данных: Приложение использует MongoDB для хранения данных о пользователях, задачах и комментариях.
Шаблонизатор: Приложение использует EJS в качестве шаблонизатора для отображения динамического контента.
Статические файлы: Приложение обслуживает статические файлы, такие как CSS, JavaScript и изображения, из каталога public.
Настройка сервера: Приложение настроено для работы на определенном порту и хосте.
Технологический стек:

Express.js (веб-фреймворк)
MongoDB (база данных)
Passport.js (библиотека аутентификации)
EJS (шаблонизатор)
CSRF (защита от атак с подделкой межсайтовых запросов)
multer (библиотека для обработки загрузки файлов)
cookie-parser (библиотека для парсинга куки)
express-session (библиотека для управления сессиями)
connect-flash (библиотека для отображения сообщений об ошибках)
body-parser (библиотека для парсинга тела запроса)
uuid (библиотека для генерации уникальных идентификаторов)
