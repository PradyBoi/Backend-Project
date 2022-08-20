const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  //   1.Create a transporterver
  const transporter = nodemailer.createTransport({
    host: process.env.USER_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.USER_EMAIL,
      pass: process.env.USER_PASSWORD,
    },
  });

  //   2.Define the email options
  const mailOptions = {
    from: 'Pradyumn Khare <pradhumnkhare@nodejs.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
  };
  //   3.Actually send the email
  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
