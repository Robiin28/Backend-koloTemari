// routes/lessonRoutes.js

const express = require('express');
const lessonController = require('../controller/lessonController');
const authController = require('../controller/authController');
const validateCourseId = require('../middleware/validateCourseId'); // Import the middleware
const router = express.Router({ mergeParams: true }); // Ensure mergeParams is set to true

// Middleware to protect routes
router.use(authController.protect);

// Middleware to validate course ID for all lesson routes under /api/courses/:courseId/lessons
router.use(validateCourseId);

// Routes

router.route('/')
    .get(lessonController.getAllLessons)
    .post(
        // authController.restrictTo('instructor', 'admin'), 
        lessonController.createLesson);

router.route('/:id')
    .get(lessonController.getLesson)
    .patch(
        // authController.restrictTo('instructor', 'admin'), 
    lessonController.updateLesson)
    .delete(
        // authController.restrictTo('instructor', 'admin'), 
        lessonController.deleteLesson);

module.exports = router;
