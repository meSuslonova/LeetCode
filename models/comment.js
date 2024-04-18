const mongoose = require('mongoose');

const CommentSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  taskId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Task',
    required: true
  },
  visibility: {
    type: String,
    default: 'public' // Устанавливаем значение по умолчанию как "всем"
  }, 
  createdAt: {
    type: Date,
    default: Date.now // Ensure default value is set to current date/time
  }
});

const Comment = mongoose.model('Comment', CommentSchema);

module.exports = Comment;
