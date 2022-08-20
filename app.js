const fs = require('fs');
const express = require('express');
const app = express();

const cookieParser = require('cookie-parser');

const paginatedResults = require('./pagination');
const controllers = require('./controllers/controllers.js');
const con = require('./db_connection.js');

app.use(express.json());
app.use(cookieParser());

const setUsers = function () {};
setUsers();

// Router
app
  .route('/quotes')
  .get(controllers.protect, paginatedResults, controllers.getQuotes)
  .post(controllers.protect, controllers.postQuote);

app.route('/getMyQuotes').get(controllers.protect, controllers.getMyQuotes);

app
  .route('/getQuotesOfTheUser')
  .post(controllers.protect, controllers.getQuotesOfTheUser);

// Delete Quote
app
  .route('/quotes/:id')
  .delete(controllers.protect, controllers.checkId, controllers.deleteQuotes);

//Register User
app.route('/register').post(controllers.registerNewUser);

// Login User
app.route('/login').post(controllers.login);

app.route('/refresh-token').post(controllers.refreshToken);

// Logout User
// controllers.protect,
app.route('/logout').post(controllers.logout);

app.route('/forgotPassword').post(controllers.forgotPassword);
app.route('/resetPassword/:token').patch(controllers.resetPassword);

module.exports = app;
