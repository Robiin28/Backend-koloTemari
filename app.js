const express = require('express');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const authRouter = require('./routes/authRouter');
const courseRouter = require('./routes/courseRoute');
const lessonRouter = require('./routes/lessonRoute');
const reviewRouter = require('./routes/reviewRoute');
const notificationRouter = require('./routes/notificationRoute');
const paymentRouter = require('./routes/paymentRoute');
const submissionRouter = require('./routes/submissionRoute');
const enrollmentRouter = require('./routes/enrollmentRoute');
const sectionRouter = require('./routes/SectionRoute');
const quizRouter = require('./routes/quizRoute');
const cartRouter = require('./routes/cartRouter');
const globalErrorHandler = require('./controller/errController');
const CustomErr = require('./utils/CustomErr');
const cors = require('cors');

const app = express();

// Enable CORS with credentials
app.use(cors({
  origin: function(origin, callback){
    if (!origin) return callback(null, true); // allow non-browser requests
    if (origin.includes('localhost:3000') || origin.endsWith('.vercel.app')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true // allow cookies
}));
app.use(cookieParser());
// Middleware
app.use(express.json());
app.use(morgan('dev'));
app.use(express.static('./public'));
// Add cookie-parser middleware

// Custom Middleware for adding request timestamp
app.use((req, res, next) => {
    req.requestedAt = new Date().toISOString();
    next();
});
// Define routes
app.use('/api/auth', authRouter);  // Authentication related routes
app.use('/api/courses', courseRouter);  // Courses related routes
app.use('/api/enrollments', enrollmentRouter);  // New route for user enrollments

// Specific route for enrolling in a course
app.use('/api/courses/:courseId/enroll', enrollmentRouter); 

// Lessons related routes for specific course and section
app.use('/api/courses/:courseId/sections/:sectionId/lessons', lessonRouter);  // Nested route for course's lessons

// Reviews related to a specific lesson
app.use('/api/lessons/:lessonId/reviews', reviewRouter);  // Reviews related routes for specific lesson

// Notifications, payments, submissions
app.use('/api/notifications', notificationRouter);  // User notifications
app.use('/api/payments', paymentRouter);  // Payment related routes
app.use('/api/submissions', submissionRouter);  // Submissions related routes

// Sections and quizzes
app.use('/api/course/:courseId/section', sectionRouter);  // Section-related routes for a specific course
app.use('/api/course/lesson/:lessonId/quiz', quizRouter);  // Quiz related to a specific lesson

// Cart related routes
app.use('/api/cart', cartRouter);

// Handle all undefined routes
app.all('*', (req, res, next) => {
    const err = new CustomErr(`Can't find ${req.originalUrl} on the server`, 404);
    next(err);
});

// Global Error Handler
app.use(globalErrorHandler);

module.exports = app;

