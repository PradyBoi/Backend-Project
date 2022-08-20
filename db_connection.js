const mysql = require('mysql');
const { promisify } = require('util');

const con = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

con.query_prom = promisify(con.query);

con.connect(function (err) {
  if (err) throw err;
  console.log('Connected!');
});

module.exports = con;
