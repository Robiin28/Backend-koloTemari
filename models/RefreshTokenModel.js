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

// Static method to create a refresh token
refreshTokenSchema.statics.createRefreshToken = async function (userId, token) {
    const expiresIn = parseInt(process.env.REFRESH_TOKEN_EXPIRES) * 1000 || 30 * 24 * 60 * 60 * 1000; // fallback 30 days
    const expiresAt = new Date(Date.now() + expiresIn);

    const refreshToken = await this.create({
        token,
        user: userId,
        expiresAt
    });

    return refreshToken;
};

// Static method to find a valid refresh token
refreshTokenSchema.statics.findValidToken = async function (userId, token) {
    return this.findOne({
        user: userId,
        token,
        expiresAt: { $gt: new Date() } // only return if not expired
    });
};

const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);
module.exports = RefreshToken;
