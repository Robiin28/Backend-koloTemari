const express = require('express');
const courseController = require('../controller/courseController');
const authController = require('../controller/authController');
const router = express.Router({ mergeParams: true });

router.route('/')
    .get(courseController.getAllCourses)

    router.use(authController.protect);  
router.route('/')   
    .post(
       authController.restrictTo('instructor', 'admin'),
       courseController.createCourse
    );
router.route('/:id')
.get(courseController.getCourse)
    .patch(authController.restrictTo('instructor', 'admin'), courseController.updateCourse)
    .delete(authController.restrictTo('instructor', 'admin'), courseController.deleteCourse);

// Route to get related courses by course ID
router.route('/:courseId/related')
    .get(courseController.getRelatedCourses);

// New route to get courses taught by a specific instructor
router.route('/instructor/:instructorId')
    .get(courseController.getCoursesByInstructor);

module.exports = router;
