const express = require('express');
const authController = require('./../controller/authController');
const userController = require('../controller/userController');

const router = express.Router();

// --------------------
// Public routes
// --------------------
router.post('/validate', authController.validateEmail);
router.get('/google', authController.googleLogin);
router.get('/google/callback', authController.googleCallback);
// git
router.get('/github', authController.githubLogin);
router.get('/github/callback', authController.githubCallback);

// New POST route for token-based GitHub login
router.post('/github/token-login', authController.githubTokenLogin);

// New POST route for token-based Google login
router.post('/google/token-login', authController.googleTokenLogin);

router.post('/validateNow', authController.validateNow);
router.post('/login', authController.login);
router.post('/signup', authController.signup);
router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);
router.post('/logout', authController.logout);
router.post('/refresh-token', authController.refreshToken);
router.get('/users/:role', userController.getUsersByRole);

// --------------------
// Protected routes
// --------------------
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
