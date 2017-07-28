var dbconfig = require('../config/database');
var mysql = require('mysql');
var connection =  mysql.createConnection(dbconfig.connection);
connection.query('USE ' + dbconfig.database);

module.exports = function (req) {

  console.log("hello",req.params.id);

  connection.query('SELECT * FROM report', function (error, results) {
    if (error) throw error;
    console.log('REPORT: ', results);
  });
};