const Enrollment = require('../models/EnrollModel');
const Course = require('../models/CourseModel');
const asyncErrorHandler = require('../utils/ErrorHandler');
const CustomErr = require('../utils/CustomErr');

exports.createEnrollment = asyncErrorHandler(async (req, res, next) => {
    const { courseId } = req.body;
    const userId = req.user._id;

    // Check if the course exists
    const course = await Course.findById(courseId);
    if (!course) {
        return next(new CustomErr('Course not found', 404));
    }

    // Check if the user is already enrolled in the course
    const existingEnrollment = await Enrollment.findOne({ student: userId, course: courseId });
    if (existingEnrollment) {
        return res.status(400).json({
            status: 'fail',
            message: 'You are already enrolled in this course.',
            data: {
                enrollment: existingEnrollment,
            },
        });
    }

    // Create the enrollment
    const enrollment = await Enrollment.create({
        student: userId,
        course: courseId,
        paymentStatus: 'completed', // Assuming the payment is handled elsewhere
        progress: 0 // Start progress at 0 for new enrollments
    });

    return res.status(201).json({
        status: 'success',
        data: {
            enrollment
        }
    });
});

// Other functions in your controller...

exports.getAllEnrollments = asyncErrorHandler(async (req, res, next) => {
    const enrollments = await Enrollment.find().populate('student course');
    res.status(200).json({
        status: 'success',
        results: enrollments.length,
        data: {
            enrollments
        }
    });
});
exports.getEnrollment = asyncErrorHandler(async (req, res, next) => {
    let enrollment;

    try {
        enrollment = await Enrollment.findById(req.params.id).populate('student course');
    } catch (err) {
        return next(new CustomErr('Invalid enrollment ID or database error', 400));
    }

    if (!enrollment) {
        // No enrollment found for that ID → success but null
        return res.status(200).json({
            status: 'success',
            data: {
                enrollment: null
            },
            message: 'No enrollment found with that ID'
        });
    }

    res.status(200).json({
        status: 'success',
        data: {
            enrollment
        }
    });
});


exports.getEnrollmentsByUser = asyncErrorHandler(async (req, res, next) => {
    const userId = req.params.id;

    let enrollments;
    try {
        enrollments = await Enrollment.find({ student: userId }).populate('student course');
    } catch (err) {
        return next(new CustomErr('Invalid user ID or database error', 400));
    }

    if (!enrollments || enrollments.length === 0) {
        return res.status(200).json({
            status: 'success',
            data: {
                enrollments: []
            },
            message: 'No enrollments found for this user'
        });
    }

    res.status(200).json({
        status: 'success',
        data: {
            enrollments
        }
    });
});



exports.getEnrollmentsByCourse = asyncErrorHandler(async (req, res, next) => {
    const courseId = req.params.courseId;

    // Find enrollments for the specified course
    const enrollments = await Enrollment.find({ course: courseId }).populate('student');

    if (enrollments.length === 0) {
        return res.status(404).json({
            status: 'fail',
            message: 'No enrollments found for this course',
        });
    }

    res.status(200).json({
        status: 'success',
        results: enrollments.length,
        data: {
            enrollments,
        },
    });
});

exports.updateProgress = asyncErrorHandler(async (req, res, next) => {
    const enrollmentId = req.params.id;
    const { progress } = req.body;

    // Validate progress value
    if (progress < 0 || progress > 100) {
        return next(new CustomErr('Progress must be between 0 and 100', 400));
    }

    // Find and update the enrollment progress
    const enrollment = await Enrollment.findByIdAndUpdate(
        enrollmentId,
        { progress },
        { new: true, runValidators: true }
    ).populate('student course');

    if (!enrollment) {
        return next(new CustomErr('No enrollment found with that ID', 404));
    }

    res.status(200).json({
        status: 'success',
        data: {
            enrollment,
        },
    });
});
exports.deleteEnrollment = asyncErrorHandler(async (req, res, next) => {
    const enrollment = await Enrollment.findByIdAndDelete(req.params.id);

    if (!enrollment) {
        return next(new CustomErr('No enrollment found with that ID', 404));
    }

    res.status(204).json({
        status: 'success',
        data: null
    });
});

exports.getProgress = asyncErrorHandler(async (req, res, next) => {
    const enrollmentId = req.params.id;

    // Find the enrollment and populate the student and course fields
    const enrollment = await Enrollment.findById(enrollmentId).populate('student course');

    if (!enrollment) {
        return next(new CustomErr('No enrollment found with that ID', 404));
    }

    res.status(200).json({
        status: 'success',
        data: {
            progress: enrollment.progress, 
            course: enrollment.course, 
            student: enrollment.student,
        },
    });
});
