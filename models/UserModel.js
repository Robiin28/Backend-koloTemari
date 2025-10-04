const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "name is required"],
        trim: true,
    },
    email: {
        type: String,
        required: [true, "please enter email is a required field"],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, "please enter valid email"],
    },
    password: {
        type: String,
        required: [true, "password is required"],
        minlength: 8,
        select: false,
    },
   confirmPassword: {
    type: String,
    required: function () {
        // Only required if provider is local signup
        return !this.provider;
    },
    validate: {
        validator: function (val) {
            if (!this.provider) return val === this.password; // validate only for normal signup
            return true; // skip validation for OAuth users
        },
        message: "password and confirm password don't match",
    },
},
provider: { type: String } // "google" or "local"
    pic: { type: String },
    passwordChangedAt: Date,
    role: {
        type: String,
        enum: ["admin", "student", "instructor"],
        default: "student",
    },
    bio: { type: String },
    active: { type: Boolean, default: false },
    passwordResetToken: String,
    passwordResetTokenExpires: Date, // Fixed name to match controller
    encryptedValidationNumber: String,
    validationNumberExpiresAt: Date,
});

// Hash password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    this.confirmPassword = undefined; // Remove confirm password
    next();
});

// Only find active users
userSchema.pre(/^find/, function (next) {
    this.where({ active: true });
    next();
});

// Compare password with hashed password in DB
userSchema.methods.comparePasswordInDb = async function (pswd, pswdDb) {
    return await bcrypt.compare(pswd, pswdDb);
};

// Check if password was changed after JWT issued
userSchema.methods.isPasswordChanged = async function (JwtTimestamp) {
    if (this.passwordChangedAt) {
        const passwdChangedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return JwtTimestamp < passwdChangedTimestamp;
    }
    return false;
};

// Create reset password token
userSchema.methods.createResetPasswordToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetTokenExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    return resetToken;
};

// Generate and encrypt validation number
userSchema.methods.generateAndEncryptValidationNumber = function () {
    const randomNumber = Math.floor(10000000 + Math.random() * 90000000).toString();
    const cipher = crypto.createHash('sha256').update(randomNumber).digest('hex');
    this.encryptedValidationNumber = cipher;
    this.validationNumberExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
    return randomNumber;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
