const express = require('express');
const controllers = require('./controllers/controllers.js');

const rateLimit = require('express-rate-limit');

const router = express.Router();

const limiter = rateLimit({
  max: 5,
  windowMs: 24 * 60 * 60 * 1000,
  message:
    'Too many requests, your account is blocked for 24 hours. Try after 24 hours or go to Forgot Password!',
});

//Register User
router.post('/register', controllers.registerNewUser);

// Login User
router.post('/login', limiter, controllers.login);

// Refresh Token
router.post('/refresh-token', controllers.refreshToken);

// Logout User
router.post('/forgotPassword', controllers.forgotPassword);

// Reset Password
router.patch('/resetPassword/:token', controllers.resetPassword);

module.exports = router;
