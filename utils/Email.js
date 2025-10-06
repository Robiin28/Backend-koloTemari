// utils/Email.js
const { google } = require('googleapis');

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN;
const SENDER_EMAIL = process.env.EMAIL_USER; // your Gmail address

// OAuth2 client
const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET);
oAuth2Client.setCredentials({ refresh_token: REFRESH_TOKEN });

const sendEmail = async ({ email, subject, html }) => {
  try {
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    // Construct raw email with proper MIME headers for HTML
    const rawMessage = [
      `From: "KolooTemari Support Team" <${SENDER_EMAIL}>`,
      `To: ${email}`,
      `Subject: ${subject}`,
      `Content-Type: text/html; charset="UTF-8"`,
      `MIME-Version: 1.0`,
      '',
      html
    ].join('\n');

    // Encode message to base64url
    const encodedMessage = Buffer.from(rawMessage)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    // Send the email
    const response = await gmail.users.messages.send({
      userId: 'me',
      requestBody: {
        raw: encodedMessage
      }
    });

    console.log('✅ Email sent successfully! Message ID:', response.data.id);
    return response.data;
  } catch (err) {
    console.error('❌ Error sending email:', err);
    throw err;
  }
};

module.exports = sendEmail;
