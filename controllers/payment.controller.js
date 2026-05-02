const connectionUserdb = require("../config/db");
const axios = require('axios');
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const APP_ID_CASHFREE = process.env.APP_ID_CASHFREE;
const SECRET_KEY_CASHFREE = process.env.SECRET_KEY_CASHFREE;
const CASHFREE_URL = process.env.CASHFREE_URL;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.createPaymentOrder = async (req, res) => {
  const { amount, customerEmail, customerPhone, redirect_url } = req.body;

  if (!amount || !customerEmail || !customerPhone) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  let customerId;

  try {
    const quary = "SELECT * FROM customers WHERE customer_phone = $1";
    const [results] = await connectionUserdb.query(quary, [customerPhone]);

    if (results.length > 0) {
       customerId = results[0].customer_id;
    } else {
      customerId = `cust_${Date.now()}`;
      try {
        const addquary = "INSERT INTO customers (customer_id, customer_phone) VALUES ($1, $2)";
        await connectionUserdb.query(addquary, [customerId, customerPhone]);
      } catch (err) {
        console.error("update cutomer err", err);
      }
    }
  
    const orderId = `ORD_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;

    const data = {
      order_amount: amount,
      order_currency: 'INR',
      customer_details: {
        customer_email: customerEmail,  
        customer_phone: customerPhone,  
        customer_id: customerId,        
      },
      order_meta: {
        notify_url: `${req.protocol}://${req.get('host')}/api/payment-donate-us/notifyurl`, 
        return_url: `${redirect_url}?order_id={order_id}&tx_status={txStatus}`,
        payment_methods: "upi,cc,dc,nb,app", 
      },
      order_id: orderId,
    };

    try {
      const response = await axios.post(CASHFREE_URL, data, {
        headers: {
          "Content-Type": "application/json",
          "accept": "application/json",
          "x-client-id": APP_ID_CASHFREE,   
          "x-client-secret": SECRET_KEY_CASHFREE,
          'x-api-version': "2023-08-01",
        }
      });

      const paymentSessionId = response.data.payment_session_id;
      const orderid = response.data.order_id;
      res.json({ paymentSessionId, orderid });
    } catch (error) {
      console.error('Error creating payment order:', error);
      res.status(500).send('Error creating payment order');
    }
  } catch (err) {
    console.error("Number findding error", err);
    res.status(500).send('Error in fetching customer data');
  }
};

const verifySignature = (bodyString, receivedSignature) => {
  const hmac = crypto.createHmac('sha256', SECRET_KEY_CASHFREE);
  hmac.update(bodyString); 
  const calculatedSignature = hmac.digest('base64');
  return receivedSignature === calculatedSignature;
};

exports.paymentNotifyUrl = (req, res) => {
  const rawBody = req.body.toString('utf8');
  req.rawBody = rawBody; 
  
  const signature = req.headers['x-webhook-signature'];  

  if (!signature) {
    return res.status(400).send('Signature missing');
  }

  if (!verifySignature(rawBody, signature)) {
    return res.status(400).send('Invalid Signature');
  }

  if (!rawBody) {
    return res.status(400).send('Invalid request, raw body missing');
  }

  res.status(200).send('Notification received successfully');
};

exports.paymentStatus = async (req, res) => {
  const { orderId } = req.params;
 
  try {
    const response = await axios.get(`${CASHFREE_URL}/${orderId}`, {
      headers: {
        "Content-Type": "application/json",
        "accept": "application/json",
        "x-client-id": APP_ID_CASHFREE,   
        "x-client-secret": SECRET_KEY_CASHFREE,
        'x-api-version': "2023-08-01",
      }
    });

    if (response.data && response.data.order_status) {
      if(response.data.order_status === "PAID"){
        const usermail = response.data.customer_details.customer_email;
       
        const mailOptions = {
          to: usermail,
          from: process.env.EMAIL_USER,
          subject: "StudyVault Payment verificaiton Message .",
          html: `
           <html>
            <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; color: #333; padding: 20px;">
              <div style="max-width: 600px; margin: auto; background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);">
                <h1 style="text-align: center; color: #4CAF50;">🎉 Payment Successful!</h1>
                <p style="text-align: center; font-size: 1.1rem; color: #555;">Thank you for your payment. Here are the details:</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <h2 style="font-size: 1.3rem;">Order Id  : <span style="font-size: 1.1rem; font-weight: 600; color: #333;">${orderId}</span></h2>
                <h2 style="font-size: 1.3rem;">Payment Status : <span style="font-size: 1.1rem; font-weight: 600; color: #333;">PAID</span></h2>
                <h2 style="font-size: 1.3rem;">Order amount : <span style="font-size: 1.1rem; font-weight: 500; color: #666;">${response.data.order_amount}</span></h2>
                <div style="background-color: #f1f1f1; padding: 15px; border-radius: 6px; margin: 20px 0;">
                  <p style="font-size: 1rem; color: #444;">Your payment has been successfully processed. Thank you for supporting Us. If you have any questions, feel free to reach out to our support team.</p>
                </div>
                <p style="font-size: 0.9rem; color: #777;">This message is related to your payment through StudyVault.</p>
                <h4 style="margin-top: 30px; color: #333;">Best regards,</h4>
                <h4 style="color: #4CAF50;">The StudyVault Team</h4>
              </div>
            </body>
          </html>
          `,
        };
      
        await transporter.sendMail(mailOptions);
      }

      res.status(200).json({
        orderId: response.data.order_id,
        status: response.data.order_status,
      });
    } else {
      res.status(400).json({ error: 'Invalid response from Cashfree' });
    }
  } catch (error) {
    console.error('Error fetching payment status:', error);
    res.status(500).json({ error: 'Failed to fetch payment status' });
  }
};
