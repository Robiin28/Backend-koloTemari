// controllers/authController.js
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { OAuth2Client } = require('google-auth-library');
const CustomErr = require('../utils/CustomErr');
const asyncErrorHandler = require('../utils/ErrorHandler');
const sendEmail = require('../utils/Email');
const crypto = require('crypto');
const util = require('util');
const axios = require('axios');
const User = require('./../models/UserModel');
const RefreshToken = require('./../models/RefreshTokenModel');



const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);



// 1️⃣ Initiate GitHub login (redirect user to GitHub)
// -----------------------------

// Initiate GitHub login (redirect to GitHub)
exports.githubLogin = (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GIT_CLIENT_ID,
    redirect_uri: process.env.GIT_REDIRECT_URL,
    scope: 'read:user user:email',
    allow_signup: 'true',
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
};
// controllers/authController.js

exports.githubCallback = async (req, res, next) => {
  try {
    const { code, error, error_description } = req.query;

    // Handle OAuth error from GitHub
    if (error) {
      const redirectUrl = `/signin?error=${encodeURIComponent(error_description || error)}`;
      return res.redirect(redirectUrl);
    }

    if (!code) {
      return res.status(400).send('GitHub authorization failed: missing code parameter');
    }

    // 1️⃣ Exchange code for access token
    const tokenResponse = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        client_id: process.env.GIT_CLIENT_ID,
        client_secret: process.env.GIT_CLIENT_SECRET,
        code,
        redirect_uri: process.env.GIT_REDIRECT_URL,
      },
      { headers: { Accept: 'application/json' } }
    );

    const accessToken = tokenResponse.data.access_token;
    if (!accessToken) {
      return res.status(400).send('Failed to get access token from GitHub');
    }

    // 2️⃣ Fetch user info from GitHub
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${accessToken}` },
    });

    const emailResponse = await axios.get('https://api.github.com/user/emails', {
      headers: { Authorization: `token ${accessToken}` },
    });

    const emails = emailResponse.data;
    const primaryEmailObj = emails.find(email => email.primary) || emails[0];
    const email = primaryEmailObj?.email;

    if (!email) {
      return res.status(400).send('Email not found from GitHub');
    }

    // 3️⃣ Create or find the user in your DB
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        name: userResponse.data.name || userResponse.data.login,
        email,
        pic: userResponse.data.avatar_url,
        password: crypto.randomBytes(32).toString('hex'),
        active: true,
        provider: 'github',
      });
    }

    console.log('✅ GitHub login successful for:', email);

    // 4️⃣ Create JWTs & save refresh token in DB
    const token = signToken(user._id);
    const refreshToken = signRefreshToken(user._id);
    await RefreshToken.createRefreshToken(user._id, refreshToken);

    // 5️⃣ Set cookies (optional, frontend can use query params)
    const accessCookieOptions = buildCookieOptions('access');
    const refreshCookieOptions = buildCookieOptions('refresh');
    res.cookie('jwt', token, accessCookieOptions);
    res.cookie('refreshToken', refreshToken, refreshCookieOptions);

    // 6️⃣ Redirect to frontend OAuth success page with tokens in query
    const frontendOrigin = process.env.FRONTEND_URL; // e.g., http://localhost:3000
    const redirectUrl = `${frontendOrigin}/oauth-success?token=${encodeURIComponent(token)}&refreshToken=${encodeURIComponent(refreshToken)}`;
    
    console.log('Redirecting to frontend with tokens:', redirectUrl); // For debugging
    return res.redirect(redirectUrl);

  } catch (err) {
    console.error('❌ GitHub login error:', err);
    next(new CustomErr('Failed to authenticate with GitHub', 500));
  }
};



// Token-based GitHub login (exchange token for user info and login)
exports.githubTokenLogin = async (req, res, next) => {
  const { token } = req.body;
  if (!token) return next(new CustomErr('GitHub token missing', 400));

  try {
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${token}` },
    });

    const emailResponse = await axios.get('https://api.github.com/user/emails', {
      headers: { Authorization: `token ${token}` },
    });

    const emails = emailResponse.data;
    const primaryEmailObj = emails.find(email => email.primary) || emails[0];
    const email = primaryEmailObj?.email;

    if (!email) return next(new CustomErr('GitHub token provided does not include an email', 400));

    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        name: userResponse.data.name || userResponse.data.login,
        email,
        pic: userResponse.data.avatar_url,
        password: crypto.randomBytes(32).toString('hex'),
        active: true,
        provider: 'github',
      });
    }

    console.log('✅ GitHub token login successful for:', email);
// removing json
    await createSendResponse(user, 200, res);
  } catch (error) {
    console.error('❌ GitHub token login error:', error);
    next(new CustomErr('Failed to authenticate with GitHub token', 500));
  }
};


exports.googleTokenLogin = asyncErrorHandler(async (req, res, next) => {
  const { token } = req.body;

  if (!token) return next(new CustomErr('Google token missing', 400));

  try {
    let payload;

    if (token.split('.').length === 3) {
      // ID token
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      payload = ticket.getPayload();
    } else if (token.startsWith('ya29')) {
      // Access token
      const { data } = await axios.get(
        `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${token}`
      );
      payload = {
        email: data.email,
        name: data.name,
        picture: data.picture,
      };
    } else {
      return next(new CustomErr('Invalid Google token', 400));
    }

    const { email, name, picture } = payload;

    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        name,
        email,
        pic: picture,
        password: crypto.randomBytes(32).toString('hex'),
        active: true,
        provider: 'google',
      });
    }

    console.log('✅ Google login successful for:', email);

    // Send only your own JWTs, never Google token
    await createSendResponse(user, 200, res);


    
  } catch (err) {
    console.error('❌ Google login error:', err);
    return next(new CustomErr('Failed to authenticate with Google', 500));
  }
});




/**
 * Duration parser helper
 * Accepts:
 *  - number or numeric string "3600" -> seconds
 *  - string with suffix "s", "m", "h", "d" -> converts to seconds
 *  - plain jwt-friendly string like "7d" is also acceptable to jwt.sign, but for cookie maxAge we convert it to ms.
 */
const parseDurationSeconds = (val) => {
    if (val === undefined || val === null) return 0;
    if (typeof val === 'number') return val;
    const s = String(val).trim();
    // If it's a plain number string like "3600", parse it
    if (/^\d+$/.test(s)) {
        return Number(s);
    }
    // If it ends with a unit
    const last = s.slice(-1).toLowerCase();
    const numPart = s.slice(0, -1);
    if (['s','m','h','d'].includes(last) && /^\d+$/.test(numPart)) {
        const n = Number(numPart);
        switch (last) {
            case 's': return n;
            case 'm': return n * 60;
            case 'h': return n * 3600;
            case 'd': return n * 86400;
            default: return 0;
        }
    }
    // fallback: try Number parse
    const maybe = Number(s);
    return Number.isNaN(maybe) ? 0 : maybe;
};

// Read env values (keep your original names)
const ACCESS_SECRET = process.env.SECRET_STR; // used throughout your code
const ACCESS_EXPIRES_RAW = process.env.LOGIN_EXPIRES; // could be "3600" or "7d"
const REFRESH_SECRET = process.env.REFRESH_TOKEN; // used to sign refresh tokens
const REFRESH_EXPIRES_RAW = process.env.REFRESH_TOKEN_EXPIRES; // e.g. "7d"

// Convert to seconds for cookie calculations
const ACCESS_EXPIRES_SEC = parseDurationSeconds(ACCESS_EXPIRES_RAW) || 0;
const REFRESH_EXPIRES_SEC = parseDurationSeconds(REFRESH_EXPIRES_RAW) || 0;

// -----------------------------
// JWT token signing function
// -----------------------------
const signToken = (id) => {
    if (!ACCESS_SECRET) {
        throw new Error("SECRET_STR is not defined");
    }
    // jwt accepts strings like "7d" or numeric seconds; we'll pass the raw to keep your config flexible
    const expiresIn = ACCESS_EXPIRES_RAW || undefined;
    return jwt.sign({ id }, ACCESS_SECRET, {
        expiresIn,
    });
};

// -----------------------------
// Refresh token signing function
// -----------------------------
const signRefreshToken = (id) => {
    if (!REFRESH_SECRET) {
        throw new Error("REFRESH_TOKEN is not defined");
    }
    const expiresIn = REFRESH_EXPIRES_RAW || undefined;
    return jwt.sign({ id }, REFRESH_SECRET, {
        expiresIn,
    });
};

// -----------------------------
// Build proper cookie options
// -----------------------------
const buildCookieOptions = (type = 'access') => {
    const isProd = process.env.NODE_ENV === 'production';
    // choose expiry
    const maxAgeMs = (type === 'access' ? ACCESS_EXPIRES_SEC : REFRESH_EXPIRES_SEC) * 1000 || undefined;

    const opts = {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? 'none' : 'lax',
    };
    if (maxAgeMs !== undefined) opts.maxAge = maxAgeMs;
    return opts;
};

// -----------------------------
// Send JWT as a cookie and response with user data
// -----------------------------
const createSendResponse = async (user, statusCode, res) => {
    const token = signToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    // Save refresh token in the database (await important)
    // Assumes RefreshToken model has createRefreshToken(userId, token) method
    await RefreshToken.createRefreshToken(user._id, refreshToken);

    // cookie options for access token and refresh token
    const accessCookieOptions = buildCookieOptions('access');
    const refreshCookieOptions = buildCookieOptions('refresh');

    // if ACCESS_EXPIRES_SEC is 0 or missing, don't set maxAge (let cookie default session)
    if (accessCookieOptions.maxAge === undefined) delete accessCookieOptions.maxAge;
    if (refreshCookieOptions.maxAge === undefined) delete refreshCookieOptions.maxAge;

    res.cookie('jwt', token, accessCookieOptions);
    res.cookie('refreshToken', refreshToken, refreshCookieOptions);

    // Remove password from output
    user.password = undefined;

    res.status(statusCode).json({
        status: 'success',
        token,
        refreshToken,
        data: { user },
    });
};

// ============================
// User signup handler
// ============================
exports.signup = asyncErrorHandler(async (req, res, next) => {
    const newUser = await User.create(req.body);
    newUser.password = undefined; // Hide password in response

    res.status(200).json({
        status: 'success',
        message: 'Now validate your email.',
    });
});
// ============================
// Email validation request handler
// ============================
// ============================
// Email validation request handler (DEBUG MODE)
// ============================
exports.validateEmail = asyncErrorHandler(async (req, res, next) => {
    const { email } = req.body;

    // Bypass the pre(/^find/) middleware to include inactive users
    const user = await User.findOne({ email, ignoreActiveFilter: true });

    console.log("Email received for validation request:", email);
    console.log("User found:", user); // Debug: check if user exists

    if (!user) {
        return next(new CustomErr("Email not found. Please sign up first.", 404));
    }

    if (user.active) {
        return next(new CustomErr("Email is already validated.", 400));
    }

    // Generate validation number and set expiration
    const validationNumber = user.generateAndEncryptValidationNumber();
    user.validationNumberExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

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
        console.error("Error sending validation email:", err);

        // Rollback validation info if email fails
        user.encryptedValidationNumber = undefined;
        user.validationNumberExpiresAt = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new CustomErr('Error sending validation email. Please try again later.', 500));
    }
});

// ============================
// Validate the validation number
// ============================
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

    // Reuse createSendResponse to set cookies and return tokens
    await createSendResponse(user, 200, res);
});

// ============================
// User login handler
// ============================
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

    await createSendResponse(user, 200, res);
});

// ============================
// Middleware to protect routes and authenticate users based on JWT in cookies
// ============================
exports.protect = asyncErrorHandler(async (req, res, next) => {
    // 1. Check Authorization header first
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.jwt) {
        token = req.cookies.jwt;
    }

    if (!token) {
        return next(new CustomErr('You are not logged in', 401));
    }

    try {
        const decodedToken = await util.promisify(jwt.verify)(token, ACCESS_SECRET);

        const user = await User.findById(decodedToken.id);
        if (!user) return next(new CustomErr('User no longer exists', 401));

        const isPasswordChanged = await user.isPasswordChanged(decodedToken.iat);
        if (isPasswordChanged) return next(new CustomErr('Password recently changed. Please login again!', 401));

        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return refreshAccessToken(req, res, next);
        }
        return next(new CustomErr('Authentication failed. Please log in again.', 401));
    }
});


// ============================
// Function to refresh the access token
// ============================
const refreshAccessToken = async (req, res, next) => {
    const refreshToken = req.cookies && req.cookies.refreshToken; // Get the refresh token from cookies

    if (!refreshToken) {
        return next(new CustomErr('You are not logged in. Please log in again.', 401));
    }

    try {
        // verify refresh token using REFRESH_SECRET (process.env.REFRESH_TOKEN)
        const decodedRefreshToken = await util.promisify(jwt.verify)(refreshToken, REFRESH_SECRET);

        // if you store refresh tokens in DB, verify it exists and is not revoked/expired
        const dbToken = await RefreshToken.findByUserIdAndToken(decodedRefreshToken.id, refreshToken);
        if (!dbToken) {
            return next(new CustomErr('Refresh token invalid or revoked. Please log in again.', 401));
        }

        const user = await User.findById(decodedRefreshToken.id);
        if (!user) {
            return next(new CustomErr('User no longer exists', 401));
        }

        // Issue a new access token
        const newAccessToken = signToken(user._id);

        const cookieOptions = buildCookieOptions('access');
        // set cookie (maxAge already set in buildCookieOptions)
        res.cookie('jwt', newAccessToken, cookieOptions);

        req.user = user; // Grant access
        return next();
    } catch (err) {
        return next(new CustomErr('Refresh token invalid or expired. Please log in again.', 401));
    }
};
// ============================
// Restrict actions to certain roles
// ============================
exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(new CustomErr('You do not have permission to perform this action', 403));
        }
        next();
    };
};

// ============================
// Forgot password handler
// ============================
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

// ============================
// Reset password handler
// ============================
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

    await createSendResponse(user, 200, res);
});

// ============================
// Logout handler
// ============================
exports.logout = asyncErrorHandler(async (req, res, next) => {
    // remove refresh token from DB if present
    const rt = req.cookies && req.cookies.refreshToken;
    if (rt) {
        try {
            await RefreshToken.deleteByToken(rt);
        } catch (e) {
            // ignore deletion errors
        }
    }

    const cookieOptions = buildCookieOptions('access');
    const refreshCookieOptions = buildCookieOptions('refresh');

    // expire cookies immediately
    res.cookie('jwt', 'logout', { ...cookieOptions, expires: new Date(Date.now() + 1000) });
    res.cookie('refreshToken', 'logout', { ...refreshCookieOptions, expires: new Date(Date.now() + 1000) });

    res.status(200).json({
        status: 'success',
        message: 'Logged out successfully',
    });
});

// ============================
// Get current logged in user details
// ============================
exports.getMe = asyncErrorHandler(async (req, res, next) => {
    res.status(200).json({
        status: 'success',
        data: {
            user: req.user,
        },
    });
});

// ============================
// Refresh token route
// ============================
exports.refreshToken = asyncErrorHandler(async (req, res, next) => {
    // Log all incoming cookies
    console.log("Incoming cookies:", req.cookies);

    const refreshToken = req.cookies && req.cookies.refreshToken;
    console.log("Refresh token received:", refreshToken);

    if (!refreshToken) {
        return next(new CustomErr('You are not logged in. Please log in again.', 401));
    }

    try {
        // Verify refresh token
        const decodedRefreshToken = await util.promisify(jwt.verify)(refreshToken, REFRESH_SECRET);
        console.log("Decoded refresh token:", decodedRefreshToken);

        // Verify refresh token exists in DB
        const dbToken = await RefreshToken.findByUserIdAndToken(decodedRefreshToken.id, refreshToken);
        if (!dbToken) {
            console.log("Refresh token not found in DB");
            return next(new CustomErr('User no longer exists', 401));
        }

        const user = await User.findById(decodedRefreshToken.id);
        if (!user) {
            console.log("User not found");
            return next(new CustomErr('User no longer exists', 401));
        }

        const newAccessToken = signToken(user._id);
        const cookieOptions = buildCookieOptions('access');
        res.cookie('jwt', newAccessToken, cookieOptions);

        req.user = user;
        return res.status(200).json({
            status: 'success',
            token: newAccessToken,
        });
    } catch (err) {
        console.log("Error verifying refresh token:", err);
        return next(new CustomErr('Refresh token invalid or expired. Please log in again.', 401));
    }
});


// ============================
// Check authentication status
// ============================
exports.checkAuth = asyncErrorHandler(async (req, res, next) => {
    if (!req.user) {
        return next(new CustomErr('You are not logged in', 401));
    }

    res.status(200).json({
        status: 'success',
        user: req.user,
    });
});
exports.googleCallback = (req, res, next) => {
  passport.authenticate('google', { failureRedirect: '/login', session: false }, async (err, user) => {
    if (err || !user) {
      return res.redirect('/login');
    }
    try {
      // Send JWT as cookie and user data in response
      await createSendResponse(user, 200, res);
    } catch (e) {
      return next(e);
    }
  })(req, res, next);
}; 
exports.googleLogin = passport.authenticate('google', {
  scope: ['profile', 'email']
});

