const express = require('express');
const cookieParser = require('cookie-parser');
const authRouter = require('./auth');
const quotesRouter = require('./quotes');

const app = express();

app.use(express.json());
app.use(cookieParser());

// AuthRouter and QuotesRouter
app.use('/', authRouter);
app.use('/', quotesRouter);

module.exports = app;
