// utils/Email.js
const Mailjet = require('node-mailjet');

if (!process.env.MAILJET_API_KEY || !process.env.MAILJET_API_SECRET) {
  throw new Error('MAILJET_API_KEY or MAILJET_API_SECRET is missing in environment variables');
}

// ✅ Correct way to initialize (works in all versions)
const mailjet = Mailjet.apiConnect
  ? Mailjet.apiConnect(process.env.MAILJET_API_KEY, process.env.MAILJET_API_SECRET)
  : Mailjet.connect(process.env.MAILJET_API_KEY, process.env.MAILJET_API_SECRET);

/**
 * Send email via Mailjet
 */
const sendEmail = async ({ email, subject, html }) => {
  try {
    const request = await mailjet
      .post('send', { version: 'v3.1' })
      .request({
        Messages: [
          {
            From: {
              Email: 'koolootemari@gmail.com', // ✅ must be verified
              Name: 'Kooloo Temari',
            },
            To: [{ Email: email }],
            Subject: subject,
            HTMLPart: html,
          },
        ],
      });

    console.log('✅ Email sent:', request.body);
  } catch (error) {
    console.error('❌ Email sending failed:', error.statusCode || error.message);
  }
};

module.exports = sendEmail;
