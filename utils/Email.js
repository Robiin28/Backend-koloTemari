const Mailjet = require('node-mailjet');

if (!process.env.MAILJET_API_KEY || !process.env.MAILJET_API_SECRET) {
  throw new Error('Mailjet API_KEY or API_SECRET is missing');
}

const mailjet = Mailjet.apiConnect(
  process.env.MAILJET_API_KEY,
  process.env.MAILJET_API_SECRET
);

const sendEmail = async ({ email, subject, html }) => {
  try {
    await mailjet
      .post("send", { version: "v3.1" })
      .request({
        Messages: [
          {
            From: {
              Email: "koolootemari@example.com", // your sender email
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
    console.log("✅ Email sent to", email);
  } catch (err) {
    console.error("❌ Email send error:", err);
    throw err;
  }
};

module.exports = sendEmail;
