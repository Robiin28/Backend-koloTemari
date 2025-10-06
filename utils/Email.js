// utils/Email.js
const nodemailer = require('nodemailer');
const { google } = require('googleapis');

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN;
const SENDER_EMAIL = process.env.EMAIL_USER; // your Gmail address

// OAuth2 client
const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET);
oAuth2Client.setCredentials({ refresh_token: REFRESH_TOKEN });

const sendEmail = async ({ email, subject, message, html }) => {
    try {
        // Generate fresh access token from refresh token
        const accessTokenObj = await oAuth2Client.getAccessToken();
        const accessToken = accessTokenObj.token;
        if (!accessToken) throw new Error('Failed to generate access token');

        // Create transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                type: 'OAuth2',
                user: SENDER_EMAIL,
                clientId: CLIENT_ID,
                clientSecret: CLIENT_SECRET,
                refreshToken: REFRESH_TOKEN,
                accessToken: accessToken
            }
        });

        // Email options
        const mailOptions = {
            from: `MineFlix Support Team <${SENDER_EMAIL}>`,
            to: email,
            subject,
            text: message,
            html
        };

        const result = await transporter.sendMail(mailOptions);
        console.log('Email sent successfully! Message ID:', result.messageId);
        return result;
    } catch (err) {
        console.error('Error sending email:', err);
        throw err;
    }
};

module.exports = sendEmail;
