const axios = require('axios');
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.verifyTurnstile = async (req, res) => {
  const { token } = req.body;

  if (!token) return res.status(400).json({ success: false, error: "No token provided" });

  try {
    const response = await axios.post(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      new URLSearchParams({
        secret: process.env.CLOUDFLARE_SECRET_KEY,
        response: token,
      })
    );
 
    if (response.data.success) {
      req.session.isVerified = true; 
      return res.json({ success: true });
    } else {
      console.error('Invalid captha');
      return res.status(400).json({ success: false, error: "Invalid captcha" });
    }
  } catch (error) {
    console.error("something error", error)
    return res.status(500).json({ success: false, error: "Server error" });
  }
};

exports.connectUsData = async (req, res) => {
  const { firstName, lastName, gmail, message } = req.query;
  const mygmail = 'ab791235@gmail.com';

  try {
    const mailOptions = {
      to: mygmail,
      from: gmail,
      subject: "StudyVault Connect fo advertising, Client message",
      html: `
        <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
              <h1 style="text-align: center;">Someone try to message you.</h1>
              <p style="text-align: center;font-size: 1.1rem">Check the details...</p>
              <p>Check the details here : </p>
              <h2 style=" margin: auto; font-size: 1.3rem;">Name - <span style=" margin: auto; font-size: 1.1rem; font-weight : 600;"> ${firstName} ${lastName} </span></h2>
              <h2 style=" margin: auto; font-size: 1.3rem;"> Gmail - <span style=" margin: auto; font-size: 1.1rem; font-weight : 600;"> ${gmail} </span></h2>
              <h2 style=" margin: auto; font-size: 1.3rem;"> Message -  ${message} </h2>
              <p>This message from advertising section.</p>
              <h4>Best regards,</h4>
              <h4>The StudyVault Team</h4>
            </div>
          </body>
        </html>
      `,
    };

    await transporter.sendMail(mailOptions);
    return res.status(200).json("Message successfully sent");
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.shortenUrl = async (req, res) => {
  try {
      const { url } = req.query;
      if (!url) return res.status(400).json({ error: "URL is required" });

      const response = await axios.get(`https://shrinkearn.com/api`, {
          params: { api: process.env.SHRINKEARN_API_KEY, url },
      });

      res.json(response.data); 
  } catch (error) {
      console.error("ShrinkEarn Error:", error);
      res.status(500).json({ error: "Failed to shorten URL" });
  }
};
