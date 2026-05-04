const connectionUserdb = require("../config/db");
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.fetchComments = async (req, res) => {
  const query = `
  SELECT c.id, c.name, c.gender, c.message, c.created_at, 
    COALESCE(
      json_agg(
        json_build_object(
          'id', r.id,
          'name', r.name,
          'gender', r.gender,
          'gmail', r.gmail,
          'message', r.message,
          'created_at', r.created_at
        )
      ) FILTER (WHERE r.id IS NOT NULL), '[]'::json
    ) AS replies
  FROM comments c
  LEFT JOIN replies r ON c.id = r.comment_id
  GROUP BY c.id
  `;

  try {
    const [results] = await connectionUserdb.query(query);
    res.json(results.map(comment => ({
      ...comment,
      replies: comment.replies || [] 
    })));
  } catch (err) {
    console.error('Error fetching comments:', err);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
};

exports.addComment = async (req, res) => {
  const { name, gmail, gender, message } = req.body;
  const query = 'INSERT INTO comments (name, gmail, gender, message) VALUES ($1, $2, $3, $4)';

  try {
    await connectionUserdb.query(query, [name, gmail, gender, message]);
    const mailOptions = {
      to: process.env.MY_GMAIL,
      from: process.env.EMAIL_USER,
      subject: "Someone Comment on StudyVault Campus",
      html: `
        <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
              <h1 >Name is :${name} <br/> Gmail is : ${gmail} <br/>  Gender :${gender} </h1>
              <h2 style=" margin: auto; font-size: 1.5rem;">This is the messsage : ${message}</h2>
              <h4>The StudyVault Campus Team</h4>
            </div>
          </body>
        </html>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.sendStatus(201);
  } catch (err) {
    console.error('Error posting comment:', err);
    res.status(500).json({ error: 'Failed to post comment' });
  }
};

exports.replyToComment = async (req, res) => {
  const { id } = req.params;
  const { name, gmail, gender, message } = req.body;

  const query = `
    INSERT INTO replies (comment_id, name, gmail, gender, message)
    VALUES ($1, $2, $3, $4, $5)
  `;

  try {
    await connectionUserdb.query(query, [id, name, gmail, gender, message]);

    const mailOptions = {
      to: process.env.MY_GMAIL,
      from: process.env.EMAIL_USER,
      subject: `Someone Replies on StudyVault Campus of this id : ${id}`,
      html: `
        <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
              <h1 >Name is :${name} <br/> Gmail is : ${gmail} <br/>  Gender :${gender} </h1>
              <h2 style=" margin: auto; font-size: 1.5rem;">This is the Reply messsage : ${message}</h2>
              <h4>The StudyVault Campus Team</h4>
            </div>
          </body>
        </html>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.sendStatus(201);
  } catch (err) {
    console.error('Error posting reply:', err);
    res.status(500).json({ error: 'Failed to post reply' });
  }
};
