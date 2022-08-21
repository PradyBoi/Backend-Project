const express = require('express');
const controllers = require('./controllers/controllers.js');

const paginatedResults = require('./pagination');

const router = express.Router();

router.use(controllers.protect);

router
  .get('/quotes', paginatedResults, controllers.getQuotes)
  .post('/quotes', controllers.postQuote);

router.get('/getMyQuotes', controllers.getMyQuotes);

router.post('/getQuotesOfTheUser', controllers.getQuotesOfTheUser);

// Delete Quote
router.delete('/quotes/:id', controllers.checkId, controllers.deleteQuotes);

module.exports = router;
