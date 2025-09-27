const express = require('express');
const sectionController = require('../controller/sectionController');
const authController = require('../controller/authController'); // Adjust the path as needed
const validateCourseId = require('../middleware/validateCourseId'); // Import the middleware

const router = express.Router({ mergeParams: true }); // Ensure mergeParams is set to true

// Protect all routes
router.use(authController.protect);

// Middleware to validate course ID for all section routes under /api/courses/:courseId/sections
router.use(validateCourseId); // Apply the middleware to all routes in this router

// Routes for managing sections within a specific course
router
    .route('/')
    .get(sectionController.getAllSections)
    .post(
        // authController.restrictTo('instructor', 'admin'),
        sectionController.createSection
    );

router
    .route('/:id')
    .get(sectionController.getSection)
    .patch(
        // authController.restrictTo('instructor', 'admin'),
        sectionController.updateSection
    )
    .delete(
        // authController.restrictTo('instructor', 'admin'),
        sectionController.deleteSection
    );

module.exports = router;
