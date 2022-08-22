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
router.route('/register').post(limiter, controllers.registerNewUser);

// Login User
router.route('/login').post(limiter, controllers.login);

// Refresh Token
router.route('/refresh-token').post(controllers.refreshToken);

// Logout User
router.route('/forgotPassword').post(controllers.forgotPassword);

// Reset Password
router.route('/resetPassword/:token').patch(controllers.resetPassword);

module.exports = router;
