function debugFileUploadMiddleware(req, res, next) {
    console.log('Debugging file upload'); // Вывод отладочного сообщения в консоль
    next(); // Передача управления следующему middleware
}
// Экспорт middleware функции для использования в других частях приложения
module.exports = debugFileUploadMiddleware;
