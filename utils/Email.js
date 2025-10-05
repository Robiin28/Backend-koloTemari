// utils/Email.js
const Mailjet = require('node-mailjet');

if (!process.env.MAILJET_API_KEY || !process.env.MAILJET_API_SECRET) {
  throw new Error('MAILJET_API_KEY or MAILJET_API_SECRET is missing in environment variables');
}

// Initialize Mailjet client correctly
const mailjet = Mailjet.connect(
  process.env.MAILJET_API_KEY,
  process.env.MAILJET_API_SECRET
);

/**
 * Send email via Mailjet
 * @param {Object} param0
 * @param {string} param0.email - Recipient email
 * @param {string} param0.subject - Email subject
 * @param {string} param0.html - HTML content of email
 */
const sendEmail = async ({ email, subject, html }) => {
  try {
    const request = await mailjet
      .post("send", { version: "v3.1" })
      .request({
        Messages: [
          {
            From: {
              Email: "koolootemari@example.com", // Replace with verified sender email
              Name: "Kooloo Temari"
            },
            To: [
              {
                Email: email,
              }
            ],
            Subject: subject,
            HTMLPart: html,
          },
        ],
      });

    console.log("✅ Email sent:", request.body);
  } catch (error) {
    console.error("❌ Email sending failed:", error);
    throw error;
  }
};

module.exports = sendEmail;
