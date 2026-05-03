const express = require("express");
const app = express();
require('dotenv').config();
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const rateLimit = require('express-rate-limit');
const session = require("express-session");
const errorHandler = require("./middleware/errorHandler");

const server = require('http').createServer(app);

const allowedOrigins = [
  "https://studyvault.space",
  "https://www.studyvault.space",
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:8081",
  "http://127.0.0.1:8081",
];

app.use(cors({
  // Allow whitelisted web origins AND React Native apps (which have no/null origin)
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: origin ${origin} not allowed`));
    }
  },
  credentials: true
}));

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(errorHandler);

server.setTimeout(300000);

app.set('trust proxy', 1); 

const limiter = rateLimit({
  windowMs: 60 * 1000, 
  max: 100, 
  handler: (req, res) => {
    console.log(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).send("Too many requests, please try again later.");
  },
});

app.use('/api/', limiter);

app.use(session({
  secret: process.env.SESSION_SECRET,   
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }    
}));

// Import Routes
const userRouter = require('./routes/userRoutes');
const adminRouter = require('./routes/adminRoutes');
const authRoutes = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');
const contentRoutes = require('./routes/contentRoutes');
const adminDataRoutes = require('./routes/adminDataRoutes');
const commentRoutes = require('./routes/commentRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const miscRoutes = require('./routes/miscRoutes');

// Mount Routes
app.use('/api/user', userRouter);
app.use('/api/Admin', adminRouter);
app.use('/api', authRoutes);
app.use('/api', profileRoutes);
app.use('/api', contentRoutes);
app.use('/api', adminDataRoutes);
app.use('/api/comments', commentRoutes);
app.use('/api', paymentRoutes);
app.use('/api', miscRoutes);

module.exports = app;