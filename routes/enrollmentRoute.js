const express = require('express');
const enrollmentController = require('../controller/enrollmentController');
const authController = require('../controller/authController');
const validateCourseId = require('../middleware/validateCourseId'); // Import the middleware
const router = express.Router({ mergeParams: true });

router.use(authController.protect);


// Route for handling enrollments
router.route('/')
    .get(enrollmentController.getAllEnrollments) // Get all enrollments
    .post(
         authController.restrictTo('student','instructor'),
         enrollmentController.createEnrollment); // Create new enrollment

router.route('/:id')
    .get(enrollmentController.getEnrollmentsByUser)
    .delete(authController.restrictTo('student', 'admin'), enrollmentController.deleteEnrollment); // Delete an enrollment by ID
router.use(validateCourseId);

router.route('/:id/progress')
    .get(authController.restrictTo('student'), enrollmentController.getProgress) // Get progress for an enrollment
    .patch(authController.restrictTo('student'), enrollmentController.updateProgress); // Update progress for an enrollment
router.route('/course/:courseId')
    .get(authController.restrictTo('instructor'), enrollmentController.getEnrollmentsByCourse); // Get enrollments for a specific course

module.exports = router;
