const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const CustomErr = require('../utils/CustomErr');
const asyncErrorHandler = require('../utils/ErrorHandler');
const sendEmail = require('../utils/Email');
const crypto = require('crypto');
const util = require('util');
const User = require('./../models/UserModel');
const RefreshToken = require('./../models/RefreshTokenModel');

// JWT token signing function
const signToken = (id) => {
    if (!process.env.SECRET_STR) {
        throw new Error("SECRET_STR is not defined");
    }
    return jwt.sign({ id }, process.env.SECRET_STR, {
        expiresIn: process.env.LOGIN_EXPIRES,
    });
};

// Send JWT as a cookie and response with user data
const createSendResponse = async (user, statusCode, res) => {
    const token = signToken(user._id);
    const refreshToken = jwt.sign(
        { id: user._id },
        process.env.REFRESH_TOKEN,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRES }
    );

    // Save refresh token in the database
    await RefreshToken.createRefreshToken(user._id, refreshToken); // add await here

    const cookieOptions = {
        maxAge: process.env.LOGIN_EXPIRES * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
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


// User signup handler
exports.signup = asyncErrorHandler(async (req, res, next) => {
    const newUser = await User.create(req.body);
    newUser.password = undefined; // Hide password in response

    res.status(200).json({
        status: 'success',
        message: 'Now validate your email.',
    });
});

// Email validation request handler
exports.validateEmail = asyncErrorHandler(async (req, res, next) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return next(new CustomErr("Email not found. Please sign up first.", 404));
    }

    if (user.active) {
        return next(new CustomErr("Email is already validated.", 400));
    }

    const validationNumber = user.generateAndEncryptValidationNumber();
    user.validationNumberExpiresAt = Date.now() + 10 * 60 * 1000;

    await user.save({ validateBeforeSave: false });

    try {
        const message = `
            <h1>Email Validation Request</h1>
            <p>Use this number to validate your account: ${validationNumber}</p>
            <p>This link will expire in 10 minutes.</p>
        `;

        await sendEmail({
            email: user.email,
            subject: 'Account Validation Number',
            html: message,
        });

        res.status(200).json({
            status: 'success',
            message: 'Account validation number sent to user email.',
        });
    } catch (err) {
        user.encryptedValidationNumber = undefined;
        user.validationNumberExpiresAt = undefined;
        await user.save({ validateBeforeSave: false });
        return next(new CustomErr('Error sending validation email. Please try again later.', 500));
    }
});

// Validate the validation number
exports.validateNow = asyncErrorHandler(async (req, res, next) => {
    const { email, validationNumber } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return next(new CustomErr("Email not found. Please sign up first.", 404));
    }

    const hashedValidationNumber = crypto.createHash('sha256').update(validationNumber.toString()).digest('hex');
    if (user.encryptedValidationNumber !== hashedValidationNumber) {
        return next(new CustomErr("Validation number is incorrect.", 400));
    }
    if (user.validationNumberExpiresAt && user.validationNumberExpiresAt < Date.now()) {
        return next(new CustomErr("Validation number has expired. Please request a new one.", 400));
    }

    user.active = true;
    user.encryptedValidationNumber = undefined;
    user.validationNumberExpiresAt = undefined;
    await user.save({ validateBeforeSave: false });

    createSendResponse(user, 200, res);
});

// User login handler
exports.login = asyncErrorHandler(async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return next(new CustomErr("Invalid email or password", 400));
    }

    const user = await User.findOne({ email }).select('+password');
    if (!user || !user.active) {
        return next(new CustomErr("No user exists with this email", 400));
    }

    const isMatch = await user.comparePasswordInDb(password, user.password);
    if (!isMatch) {
        return next(new CustomErr("Incorrect email or password", 400));
    }

    createSendResponse(user, 200, res);
});

// Middleware to protect routes and authenticate users based on JWT in cookies
exports.protect = asyncErrorHandler(async (req, res, next) => {
    const token = req.cookies.jwt; // Get the token from the cookie

    if (!token) {
        return next(new CustomErr('You are not logged in', 401));
    }

    try {
        const decodedToken = await util.promisify(jwt.verify)(token, process.env.SECRET_STR);
        
        const user = await User.findById(decodedToken.id);
        if (!user) {
            return next(new CustomErr('The user no longer exists with this token', 401));
        }

        const isPasswordChanged = await user.isPasswordChanged(decodedToken.iat);
        if (isPasswordChanged) {
            return next(new CustomErr('The password was changed recently. Please log in again!', 401));
        }

        req.user = user; // Grant access
        return next();

    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return refreshAccessToken(req, res, next);
        }
        return next(new CustomErr('Authentication failed. Please log in again.', 401));
    }
});

// Function to refresh the access token
const refreshAccessToken = async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken; // Get the refresh token from cookies

    if (!refreshToken) {
        return next(new CustomErr('You are not logged in. Please log in again.', 401));
    }

    try {
        const decodedRefreshToken = await util.promisify(jwt.verify)(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        
        const user = await User.findById(decodedRefreshToken.id);
        if (!user) {
            return next(new CustomErr('User no longer exists', 401));
        }

        // Issue a new access token
        const newAccessToken = signToken(user._id);
        res.cookie('jwt', newAccessToken, {
            maxAge: process.env.LOGIN_EXPIRES * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none', // Changed for deployment
        });

        req.user = user; // Grant access
        return next();
    } catch (err) {
        return next(new CustomErr('Refresh token invalid or expired. Please log in again.', 401));
    }
};

// Restrict actions to certain roles
exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(new CustomErr('You do not have permission to perform this action', 403));
        }
        next();
    };
};

// Forgot password handler
exports.forgotPassword = asyncErrorHandler(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user || !user.active) {
        return next(new CustomErr('We could not find the user', 404));
    }

    const resetToken = user.createResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    const resetUrl = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;
    const message = `
        <h1>Password Reset Request</h1>
        <p>Reset your password using this link: <a href="${resetUrl}">Reset Password</a></p>
        <p>This link will expire in 10 minutes.</p>
    `;

    try {
        await sendEmail({
            email: user.email,
            subject: "Password Reset Request",
            html: message,
        });

        res.status(200).json({
            status: 'success',
            message: "Password reset email sent to user email",
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetTokenExpires = undefined;
        await user.save({ validateBeforeSave: false });
        return next(new CustomErr("Error sending password reset email. Please try again later", 500));
    }
});

// Reset password handler
exports.resetPassword = asyncErrorHandler(async (req, res, next) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
        return next(new CustomErr("Token is invalid or has expired", 400));
    }

    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpires = undefined;
    await user.save();

    createSendResponse(user, 200, res);
});

// Logout handler
exports.logout = asyncErrorHandler(async (req, res, next) => {
    res.cookie('jwt', 'logout', {
        expires: new Date(Date.now() + 1000),
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'none',
    });

    res.cookie('refreshToken', 'logout', {
        expires: new Date(Date.now() + 1000),
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'none',
    });

    res.status(200).json({
        status: 'success',
        message: 'Logged out successfully',
    });
});

// Get current logged in user details
exports.getMe = asyncErrorHandler(async (req, res, next) => {
    res.status(200).json({
        status: 'success',
        data: {
            user: req.user,
        },
    });
});

// Refresh token route
exports.refreshToken = asyncErrorHandler(async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return next(new CustomErr('You are not logged in. Please log in again.', 401));
    }

    try {
        const decodedRefreshToken = await util.promisify(jwt.verify)(refreshToken, process.env.REFRESH_TOKEN);
        
        const user = await User.findById(decodedRefreshToken.id);
        if (!user) {
            return next(new CustomErr('User no longer exists', 401));
        }

        const newAccessToken = signToken(user._id);
        res.cookie('jwt', newAccessToken, {
            maxAge: process.env.LOGIN_EXPIRES * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
        });

        req.user = user;
        return res.status(200).json({
            status: 'success',
            token: newAccessToken,
        });
    } catch (err) {
        return next(new CustomErr('Refresh token invalid or expired. Please log in again.', 401));
    }
});

// Check authentication status
exports.checkAuth = asyncErrorHandler(async (req, res, next) => {
    if (!req.user) {
        return next(new CustomErr('You are not logged in', 401));
    }

    res.status(200).json({
        status: 'success',
        user: req.user,
    });
});
