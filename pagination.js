const con = require('./db_connection.js');

let model = null;

module.exports = async function paginatedResults(req, res, next) {
  if (!model) {
    model = await con.query_prom(
      'SELECT Id, Quote FROM Quotes WHERE isDeleted=?',
      [0]
    );
  }

  const page = Number.parseInt(req.query.page || 1, 10);
  const limit = Number.parseInt(req.query.limit || model.length, 10);

  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;

  const results = {};

  if (endIndex < model.length) {
    results.next = {
      page: page + 1,
      limit: limit,
    };
  }

  if (startIndex > 0) {
    results.previous = {
      page: page - 1,
      limit: limit,
    };
  }

  results.results = model.slice(startIndex, endIndex);

  res.paginatedResults = results;
  next();
};
