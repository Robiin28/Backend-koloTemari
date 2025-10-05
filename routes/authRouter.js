const express = require('express');
const authController = require('./../controller/authController');
const userController = require('../controller/userController');
const passport = require('passport');

const router = express.Router();

const FRONTEND_URL = process.env.FRONTEND_URL;

// --------------------
// Public routes
// --------------------
router.post('/validate', authController.validateEmail);
router.get('/google', authController.googleLogin);
router.get('/google/callback', authController.googleCallback);

// --------------------
// GitHub OAuth --------------------
router.get(
  '/github',
  passport.authenticate('github', { scope: ['user:email'], session: false })
);

// Google callback route
router.get('/github/callback', authController.githubCallback);
// --------------------
// Token-based login routes --------------------
router.post('/github/token-login', authController.githubTokenLogin);
router.post('/google/token-login', authController.googleTokenLogin);

// --------------------
// Other auth routes --------------------
router.post('/validateNow', authController.validateNow);
router.post('/login', authController.login);
router.post('/signup', authController.signup);
router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);
router.post('/logout', authController.logout);
router.post('/refresh-token', authController.refreshToken);
router.get('/users/:role', userController.getUsersByRole);

// --------------------
// Protected routes --------------------
router.use(authController.protect);

router.get('/check', authController.checkAuth);
router.get('/users', userController.getUsers);
router.get('/me', userController.getMe);
router.get('/users/:id', userController.getUserById);

router.patch('/updatePassword', userController.updatePassword);
router.patch('/updateMe', userController.updateMe);
router.delete('/deleteMe', userController.deleteMe);
router.delete('/deleteUser/:id', userController.deleteUser);

module.exports = router;
