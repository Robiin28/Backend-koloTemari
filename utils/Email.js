// utils/Email.js
const Mailjet = require('node-mailjet');

const mailjet = Mailjet.connect(
  process.env.MJ_APIKEY_PUBLIC,
  process.env.MJ_APIKEY_PRIVATE
);

/**
 * Send an email via Mailjet
 * @param {Object} options - { email, subject, html }
 */
const sendEmail = async ({ email, subject, html }) => {
  try {
    const request = mailjet
      .post('send', { version: 'v3.1' })
      .request({
        Messages: [
          {
            From: {
              Email: 'KoolooTemari@gmail.com',
              Name: 'KoloTemari Team',
            },
            To: [{ Email: email }],
            Subject: subject,
            HTMLPart: html, // HTML content goes here
          },
        ],
      });

    const result = await request;
    console.log('✅ Email sent:', result.body);
    return result.body;
  } catch (err) {
    console.error('❌ Email failed:', err);
    throw err;
  }
};

module.exports = sendEmail;
