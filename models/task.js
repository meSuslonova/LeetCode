const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    difficulty: {
        type: String,
        required: true,
        enum: ['easy', 'medium', 'hard'],
        default: ['easy'] // Устанавливаем значение по умолчанию как "всем"
    },
    tags: {
        type: [String],
        required: true
    },
    files: {
        type: [String],
        required: true
    },
    links: [{
        url: String,
        title: String
    }],
    visibility: {
        type: String,
        default: 'public' // Устанавливаем значение по умолчанию как "всем"
    }
});

const Task = mongoose.model('Task', taskSchema);

module.exports = Task;