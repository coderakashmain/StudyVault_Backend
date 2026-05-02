const express = require('express');
const router = express.Router();

const {
  createPaymentOrder,
  paymentNotifyUrl,
  paymentStatus
} = require('../controllers/payment.controller');

router.post('/create-payment-order', createPaymentOrder);
router.post('/payment-donate-us/notifyurl', express.raw({ type: 'application/json' }), paymentNotifyUrl);
router.get('/payment-status/:orderId', paymentStatus);

module.exports = router;
