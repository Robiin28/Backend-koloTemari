const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const util = require('util');
const User = require('../models/UserModel');
const RefreshToken = require('../models/RefreshTokenModel');
const CustomErr = require('../utils/CustomErr');
const asyncErrorHandler = require('../utils/ErrorHandler');
const sendEmail = require('../utils/Email');

// Sign JWT token
const signToken = (id) => {
    if (!process.env.SECRET_STR) throw new Error("SECRET_STR is not defined");
    return jwt.sign({ id }, process.env.SECRET_STR, {
        expiresIn: process.env.LOGIN_EXPIRES,
    });
};

// Send JWT and refresh token as cookies and response
const createSendResponse = async (user, statusCode, res) => {
    const token = signToken(user._id);
    const refreshToken = jwt.sign(
        { id: user._id },
        process.env.REFRESH_TOKEN,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRES }
    );

    // Save refresh token in DB
    await RefreshToken.createRefreshToken(user._id, refreshToken);

    const cookieOptions = {
        maxAge: parseInt(process.env.LOGIN_EXPIRES) * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'none'
    };

    res.cookie('jwt', token, cookieOptions);
    res.cookie('refreshToken', refreshToken, cookieOptions);

    user.password = undefined;
    res.status(statusCode).json({
        status: 'success',
        token,
        refreshToken,
        data: { user },
    });
};

// Signup
exports.signup = asyncErrorHandler(async (req, res, next) => {
    const newUser = await User.create(req.body);
    newUser.password = undefined;
    res.status(200).json({
        status: 'success',
        message: 'Signup successful. Now validate your email.'
    });
});

// Email validation
exports.validateEmail = asyncErrorHandler(async (req, res, next) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return next(new CustomErr("Email not found", 404));
    if (user.active) return next(new CustomErr("Email already validated", 400));

    const validationNumber = user.generateAndEncryptValidationNumber();
    await user.save({ validateBeforeSave: false });

    try {
        await sendEmail({
            email: user.email,
            subject: "Account Validation Number",
            html: `<h1>Validate Your Account</h1><p>Use this number: ${validationNumber}</p><p>Expires in 10 minutes.</p>`
        });
        res.status(200).json({ status: 'success', message: "Validation number sent" });
    } catch (err) {
        user.encryptedValidationNumber = undefined;
        user.validationNumberExpiresAt = undefined;
        await user.save({ validateBeforeSave: false });
        return next(new CustomErr("Error sending email", 500));
    }
});

// Validate now
exports.validateNow = asyncErrorHandler(async (req, res, next) => {
    const { email, validationNumber } = req.body;
    const user = await User.findOne({ email });
    if (!user) return next(new CustomErr("Email not found", 404));

    const hashedNumber = crypto.createHash('sha256').update(validationNumber.toString()).digest('hex');

    if (user.encryptedValidationNumber !== hashedNumber) return next(new CustomErr("Invalid number", 400));
    if (user.validationNumberExpiresAt && user.validationNumberExpiresAt < Date.now())
        return next(new CustomErr("Validation number expired", 400));

    user.active = true;
    user.encryptedValidationNumber = undefined;
    user.validationNumberExpiresAt = undefined;
    await user.save({ validateBeforeSave: false });

    await createSendResponse(user, 200, res);
});

// Login
exports.login = asyncErrorHandler(async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) return next(new CustomErr("Provide email and password", 400));

    const user = await User.findOne({ email }).select('+password');
    if (!user || !user.active) return next(new CustomErr("No active user found", 400));

    const isMatch = await user.comparePasswordInDb(password, user.password);
    if (!isMatch) return next(new CustomErr("Incorrect password", 400));

    await createSendResponse(user, 200, res);
});

// Protect middleware
exports.protect = asyncErrorHandler(async (req, res, next) => {
    let token = req.cookies.jwt;
    if (!token) return next(new CustomErr("Not logged in", 401));

    try {
        const decoded = await util.promisify(jwt.verify)(token, process.env.SECRET_STR);
        const user = await User.findById(decoded.id);
        if (!user) return next(new CustomErr("User no longer exists", 401));

        const passwordChanged = await user.isPasswordChanged(decoded.iat);
        if (passwordChanged) return next(new CustomErr("Password changed recently. Log in again.", 401));

        req.user = user;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return exports.refreshAccessToken(req, res, next);
        }
        return next(new CustomErr("Authentication failed", 401));
    }
});

// Refresh access token
exports.refreshAccessToken = asyncErrorHandler(async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return next(new CustomErr("No refresh token. Login again.", 401));

    try {
        const decoded = await util.promisify(jwt.verify)(refreshToken, process.env.REFRESH_TOKEN);
        const user = await User.findById(decoded.id);
        if (!user) return next(new CustomErr("User not found", 401));

        const dbToken = await RefreshToken.findValidToken(user._id, refreshToken);
        if (!dbToken) return next(new CustomErr("Invalid or expired refresh token", 401));

        const newAccessToken = signToken(user._id);
        res.cookie('jwt', newAccessToken, {
            maxAge: parseInt(process.env.LOGIN_EXPIRES) * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none'
        });

        req.user = user;
        next();
    } catch (err) {
        return next(new CustomErr("Refresh token invalid. Login again.", 401));
    }
});

// Logout
exports.logout = asyncErrorHandler(async (req, res, next) => {
    res.cookie('jwt', 'logout', { expires: new Date(Date.now() + 1000), httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'none' });
    res.cookie('refreshToken', 'logout', { expires: new Date(Date.now() + 1000), httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'none' });
    res.status(200).json({ status: 'success', message: 'Logged out successfully' });
});

// Check auth
exports.checkAuth = asyncErrorHandler(async (req, res, next) => {
    if (!req.user) return next(new CustomErr("Not logged in", 401));
    res.status(200).json({ status: 'success', user: req.user });
});
