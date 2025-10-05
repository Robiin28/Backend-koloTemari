const nodemailer = require('nodemailer');

const sendEmail = async (option) => {
  try {
    // Create transporter with SSL and TLS options
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST, // smtp.gmail.com
      port: Number(process.env.EMAIL_PORT), // 465
      secure: true, // SSL
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD, // Gmail App Password
      },
      tls: {
        rejectUnauthorized: false, // needed on some cloud servers
      },
      connectionTimeout: 15000, // 15 seconds
    });

    // Verify SMTP connection before sending
    await transporter.verify();
    console.log('SMTP connection verified');

    // Email options
    const emailOption = {
      from: `KoloTemari team <${process.env.EMAIL_USER}>`,
      to: option.email,
      subject: option.subject,
      text: option.message || '', // plain text fallback
      html: option.html || '',     // your HTML content
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
