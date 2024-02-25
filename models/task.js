const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
    description: {
        type: String,
        required: true
    },
    input: {
        type: String,
        required: true
    },
    output: {
        type: String,
        required: true
    },
    difficulty: {
        type: String,
        required: true,
        enum: ['easy', 'medium', 'hard']
    },
    tags: {
        type: [String],
        required: true
    },
    additionalMaterials: {
        type: [String]
    }
});

const Task = mongoose.model('Task', taskSchema);

module.exports = Task;
