const nodemailer = require('nodemailer');

const sendEmail = async (option) => {
  try {
    // Create transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: Number(process.env.EMAIL_PORT),
      secure: process.env.EMAIL_PORT == 465, // true for port 465, false for 587
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    // Email options
    const emailOption = {
      from: 'KoloTemari team <KoolooTemari@gmail.com>', // fixed the < >
      to: option.email,
      subject: option.subject,
      text: option.message,
      html: option.html,
    };

    // Send email
    const info = await transporter.sendMail(emailOption);
    console.log('Email sent:', info.response);
    return info;
  } catch (error) {
    console.error('Email failed:', error);
    throw error;
  }
};

module.exports = sendEmail;
