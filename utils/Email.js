// utils/Email.js
const nodemailer = require('nodemailer');
const { google } = require('googleapis');

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'https://developers.google.com/oauthplayground';
const REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN;

const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
oAuth2Client.setCredentials({ refresh_token: REFRESH_TOKEN });

const sendEmail = async (options) => {
    try {
        // get a fresh access token
        const accessTokenObj = await oAuth2Client.getAccessToken();
        const accessToken = accessTokenObj.token;

        if (!accessToken) throw new Error("Failed to generate access token");

        // create transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                type: 'OAuth2',
                user: process.env.EMAIL_USER, // your Gmail address
                clientId: CLIENT_ID,
                clientSecret: CLIENT_SECRET,
                refreshToken: REFRESH_TOKEN,
                accessToken: accessToken
            }
        });

        // email options
        const mailOptions = {
            from: `MineFlix Support Team <${process.env.EMAIL_USER}>`,
            to: options.email,
            subject: options.subject,
            text: options.message,
            html: options.html
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

