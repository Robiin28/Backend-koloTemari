const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    }
});

// Static method to create a new refresh token
refreshTokenSchema.statics.createRefreshToken = async function (userId, token) {
    // 30 days expiration
    const expiresIn = 30 * 24 * 60 * 60 * 1000; // 30 days in ms
    const expiresAt = new Date(Date.now() + expiresIn);

    // Save the refresh token in the database
    const refreshToken = await this.create({
        token,
        user: userId,
        expiresAt
    });

    return refreshToken;
};

// Static method to find a valid token by token string
refreshTokenSchema.statics.findValidToken = async function (token) {
    const doc = await this.findOne({ token, expiresAt: { $gt: Date.now() } });
    return doc;
};

// Static method to find a token by userId and token
refreshTokenSchema.statics.findByUserIdAndToken = async function(userId, token) {
    const doc = await this.findOne({ user: userId, token, expiresAt: { $gt: Date.now() } });
    return doc;
};

// Static method to delete a token (e.g., for logout)
refreshTokenSchema.statics.deleteToken = async function (token) {
    await this.deleteOne({ token });
};

const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);

module.exports = RefreshToken;
