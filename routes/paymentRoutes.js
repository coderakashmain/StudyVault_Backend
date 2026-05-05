const express = require('express');
const router = express.Router();

const {
  createPaymentOrder,
  paymentNotifyUrl,
  paymentStatus,
  saveTransaction,
  getTransactionHistory
} = require('../controllers/payment.controller');
const { verifyAuth } = require('../middleware/authHandler');

router.post('/create-payment-order', createPaymentOrder);
router.post('/payment-donate-us/notifyurl', express.raw({ type: 'application/json' }), paymentNotifyUrl);
router.get('/payment-status/:orderId', paymentStatus);

// History & Logging (Protected)
router.get('/payment/history', verifyAuth, getTransactionHistory);
router.post('/payment/log', verifyAuth, saveTransaction);

module.exports = router;
