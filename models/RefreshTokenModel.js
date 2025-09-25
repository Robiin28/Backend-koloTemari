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

// Static method to create refresh token
refreshTokenSchema.statics.createRefreshToken = async function (userId, token) {
    const expiresIn = 30 * 24 * 60 * 60 * 1000; // 30 days
    const expiresAt = new Date(Date.now() + expiresIn);

    const refreshToken = await this.create({
        token,
        user: userId,
        expiresAt
    });

    return refreshToken;
};

const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);

module.exports = RefreshToken;
