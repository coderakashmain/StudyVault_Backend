const connectionUserdb = require("../config/db");
const asyncHandler = require("../middleware/asyncHandler");
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

  try {
    if (!amount || isNaN(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount provided' });
    }

    // Check if user has an existing email in profile for fallback
    const userId = req.user.id;
    const [userRows] = await connectionUserdb.query("SELECT gmail FROM users WHERE id = $1", [userId]);
    
    if (userRows.length > 0) {
      const user = userRows[0];
      if (!customerEmail && user.gmail) customerEmail = user.gmail;
    }

    // customerPhone must come from the request body since it's not in the users table
    if (!customerEmail || !customerPhone) {
      return res.status(400).json({ error: 'Email and Phone are required for payment' });
    }
  
    // Ensure amount is a number and formatted correctly (2 decimal places)
    const formattedAmount = Number(amount).toFixed(2);

    // Clean phone number (remove non-digits, ensure length)
    const cleanPhone = customerPhone.replace(/\D/g, '').slice(-10);
    if (cleanPhone.length < 10) {
      return res.status(400).json({ error: 'A valid 10-digit phone number is required' });
    }
  
    // Create a structured Order ID that includes the User ID for easy tracking in webhooks
    const orderId = `SV_${req.user.id}_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

    const data = {
      order_amount: formattedAmount,
      order_currency: 'INR',
      customer_details: {
        customer_email: customerEmail,  
        customer_phone: cleanPhone,  
        customer_id: `USER_${req.user.id}`,        
      },
      order_meta: {
        notify_url: `${req.protocol}://${req.get('host')}/api/payment-donate-us/notifyurl`, 
        return_url: `https://studyvault.space/payment-success?order_id={order_id}`,
        payment_methods: "upi,cc,dc,nb,app", 
      },
      order_id: orderId,
    };

    console.log("Initiating Cashfree Order:", orderId, "Amount:", formattedAmount);

    const response = await axios.post(CASHFREE_URL, data, {
      headers: {
        "Content-Type": "application/json",
        "x-client-id": APP_ID_CASHFREE,   
        "x-client-secret": SECRET_KEY_CASHFREE,
        'x-api-version': "2023-08-01",
      }
    });

    res.status(200).json({
      paymentSessionId: response.data.payment_session_id,
      orderid: response.data.order_id,
    });

  } catch (error) {
    const errorData = error.response?.data || error.message;
    console.error('Cashfree API Error:', JSON.stringify(errorData, null, 2));
    
    res.status(500).json({ 
      error: 'Failed to create payment order',
      details: error.response?.data?.message || error.message 
    });
  }
};

const verifySignature = (rawBody, receivedSignature) => {
  const secretKey = SECRET_KEY_CASHFREE;
  const calculatedSignature = crypto
    .createHmac('sha256', secretKey)
    .update(rawBody)
    .digest('base64');
  return receivedSignature === calculatedSignature;
};

exports.paymentNotifyUrl = async (req, res) => {
  try {
    const rawBody = req.body.toString('utf8');
    const signature = req.headers['x-webhook-signature'];  

    if (!signature) {
      return res.status(400).send('Signature missing');
    }

    if (!verifySignature(rawBody, signature)) {
      console.error('Webhook Signature Verification Failed');
      return res.status(400).send('Invalid Signature');
    }

    const payload = JSON.parse(rawBody);
    console.log("Cashfree Webhook Received:", payload.event_type);

    if (payload.event_type === 'ORDER_PAID') {
      const { order, payment } = payload.data;
      const orderId = order.order_id;
      const amount = order.order_amount;
      
      // Determine transaction type and details
      let transactionType = 'Contribution';
      let creditAmount = 0;
      let userId = null;

      const parts = orderId.split('_');
      if (parts[0] === 'SV') {
        userId = parts[1];
        transactionType = 'Contribution';
      } else if (parts[0] === 'CR') {
        userId = parts[1];
        creditAmount = parseInt(parts[2]) || 0;
        transactionType = 'Credit Top-up';
      }

      if (userId) {
        // Log the transaction to DB if not already present
        const checkSql = "SELECT * FROM user_transactions WHERE transaction_id = $1";
        const [existing] = await connectionUserdb.query(checkSql, [orderId]);
        
        if (existing.length === 0) {
          const logSql = `
            INSERT INTO user_transactions (user_id, transaction_id, amount, type, status, details, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
          `;
          await connectionUserdb.query(logSql, [
            userId,
            orderId,
            amount,
            transactionType,
            'SUCCESS',
            transactionType === 'Credit Top-up' ? `Method: ${payment.payment_group} - Credits: ${creditAmount}` : `Method: ${payment.payment_group || 'UPI'}`,
            Date.now()
          ]);

          // If it's a credit purchase, update the user's credits balance
          if (transactionType === 'Credit Top-up' && creditAmount > 0) {
            await connectionUserdb.query(
              "UPDATE users SET credits = COALESCE(credits, 0) + $1 WHERE id = $2",
              [creditAmount, userId]
            );
            console.log(`Successfully added ${creditAmount} credits to user ${userId} via webhook`);
          }

          console.log(`Transaction ${orderId} (${transactionType}) logged via webhook for user ${userId}`);
        }
      }
    }

    res.status(200).send('Notification received successfully');
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).send('Internal Server Error');
  }
};

exports.paymentStatus = async (req, res) => {
  const { orderId } = req.params;
  console.log("Checking payment status for:", orderId);
 
  try {
    const response = await axios.get(`${CASHFREE_URL}/${orderId}`, {
      headers: {
        "Content-Type": "application/json",
        "accept": "application/json",
        "x-client-id": APP_ID_CASHFREE,   
        "x-client-secret": SECRET_KEY_CASHFREE,
        'x-api-version': "2023-08-01",
      },
      timeout: 10000 // 10s timeout for Cashfree API
    });

    const orderData = response.data;
    const isPaid = orderData.order_status === "PAID";

    if (isPaid) {
      // Determine transaction type and details based on order prefix
      let transactionType = 'Contribution';
      let creditAmount = 0;
      let userId = null;

      const parts = orderId.split('_');
      if (parts[0] === 'SV') {
        userId = parts[1];
        transactionType = 'Contribution';
      } else if (parts[0] === 'CR') {
        userId = parts[1];
        creditAmount = parseInt(parts[2]) || 0;
        transactionType = 'Credit Top-up';
      }

      if (userId) {
        // Log the transaction to DB if not already present
        const checkSql = "SELECT * FROM user_transactions WHERE transaction_id = $1";
        const [existing] = await connectionUserdb.query(checkSql, [orderId]);
        
        if (existing.length === 0) {
          const logSql = `
            INSERT INTO user_transactions (user_id, transaction_id, amount, type, status, details, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
          `;
          await connectionUserdb.query(logSql, [
            userId,
            orderId,
            orderData.order_amount,
            transactionType,
            'SUCCESS',
            transactionType === 'Credit Top-up' ? `Added ${creditAmount} credits` : 'Verified via Status Check',
            Date.now()
          ]);

          // If it's a credit purchase, update the user's credits balance
          if (transactionType === 'Credit Top-up' && creditAmount > 0) {
            await connectionUserdb.query(
              "UPDATE users SET credits = COALESCE(credits, 0) + $1 WHERE id = $2",
              [creditAmount, userId]
            );
            console.log(`Successfully added ${creditAmount} credits to user ${userId} via status check`);
          }

          console.log(`Transaction ${orderId} (${transactionType}) logged via status check fallback`);
        }
      }

      const usermail = orderData.customer_details.customer_email;
      if (usermail) {
        const mailOptions = {
          to: usermail,
          from: process.env.EMAIL_USER,
          subject: "StudyVault Campus - Contribution Received!",
          html: `
            <div style="font-family: sans-serif; padding: 20px;">
              <h1 style="color: #4CAF50;">🎉 Thank You!</h1>
              <p>We've received your contribution of <b>₹${orderData.order_amount}</b>.</p>
              <p>Order ID: <b>${orderId}</b></p>
              <p>Your support helps us keep the platform free for all students.</p>
            </div>
          `
        };
        transporter.sendMail(mailOptions).catch(e => console.error("Email error:", e));
      }
    }

    return res.status(200).json({
      status: orderData.order_status,
      amount: orderData.order_amount,
      isSuccess: isPaid
    });

  } catch (error) {
    console.error('Cashfree Status Error:', error.response?.data || error.message);
    return res.status(500).json({ 
      error: "Failed to verify payment with gateway",
      details: error.response?.data || error.message
    });
  }
};

/**
 * Save a new transaction log
 */
exports.saveTransaction = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { id, amount, type, status, details } = req.body;

  if (!id || !amount || !type) return res.status(400).json({ error: "Missing transaction details" });

  const sql = `
    INSERT INTO user_transactions (user_id, transaction_id, amount, type, status, details, timestamp)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
  `;

  await connectionUserdb.query(sql, [
    userId, 
    id, 
    amount, 
    type, 
    status || 'SUCCESS', 
    details || '', 
    Date.now()
  ]);

  res.status(200).json({ success: true });
});

exports.getTransactionHistory = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const sql = "SELECT * FROM user_transactions WHERE user_id = $1 ORDER BY timestamp DESC";
  const [rows] = await connectionUserdb.query(sql, [userId]);
  res.status(200).json({ success: true, data: rows });
});
