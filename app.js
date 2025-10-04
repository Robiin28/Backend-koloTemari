const express = require('express');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');

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

require('./utils/passport'); // Your passport configuration file that sets up strategies

const app = express();

// ----------------------------
// CORS configuration
// ----------------------------
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true); // allow non-browser requests like Postman
    if (origin.includes('localhost:3000') || origin.endsWith('.vercel.app') || origin.endsWith('.onrender.com')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies
}));

// ----------------------------
// Middleware
// ----------------------------
app.use(cookieParser());
app.use(express.json());
app.use(morgan('dev'));
app.use(express.static('./public'));

// Setup session middleware for passport
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    // your cookie config options here
  },
}));

// Initialize Passport and use passport sessions
app.use(passport.initialize());
app.use(passport.session());

// Custom Middleware: request timestamp
app.use((req, res, next) => {
  req.requestedAt = new Date().toISOString();
  next();
});

// ----------------------------
// Routes
// ----------------------------
app.use('/api/auth', authRouter);
app.use('/api/courses', courseRouter);
app.use('/api/enrollments', enrollmentRouter);
app.use('/api/courses/:courseId/enroll', enrollmentRouter);
app.use('/api/courses/:courseId/sections/:sectionId/lessons', lessonRouter);
app.use('/api/lessons/:lessonId/reviews', reviewRouter);
app.use('/api/notifications', notificationRouter);
app.use('/api/payments', paymentRouter);
app.use('/api/submissions', submissionRouter);
app.use('/api/course/:courseId/section', sectionRouter);
app.use('/api/course/lesson/:lessonId/quiz', quizRouter);
app.use('/api/cart', cartRouter);

// ----------------------------
// Handle undefined routes
// ----------------------------
app.all('*', (req, res, next) => {
  next(new CustomErr(`Can't find ${req.originalUrl} on the server`, 404));
});

// ----------------------------
// Global error handler
// ----------------------------
app.use(globalErrorHandler);

module.exports = app;
