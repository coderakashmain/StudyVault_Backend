const express = require('express');
const router = express.Router();

const {
  createPaymentOrder,
  paymentNotifyUrl,
  paymentStatus,
  saveTransaction,
  getTransactionHistory,
  // submitUpiUtr, // commented out - using Cashfree gateway instead
} = require('../controllers/payment.controller');
const { verifyAuth } = require('../middleware/authHandler');

router.post('/create-payment-order', verifyAuth, createPaymentOrder);
router.post('/payment-donate-us/notifyurl', express.raw({ type: 'application/json' }), paymentNotifyUrl);
router.get('/payment-status/:orderId', paymentStatus);

// History & Logging (Protected)
router.get('/payment/history', verifyAuth, getTransactionHistory);
router.post('/payment/log', verifyAuth, saveTransaction);

// Free UPI Payment via UTR verification (commented out - using Cashfree gateway instead)
// router.post('/payment/upi-utr', verifyAuth, submitUpiUtr);

module.exports = router;
