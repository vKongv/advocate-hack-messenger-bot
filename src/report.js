var dbconfig = require('../config/database');
var mysql = require('mysql');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var Promise = require('bluebird');
var connection =  Promise.promisifyAll(mysql.createConnection(dbconfig.connection));
connection.query('USE ' + dbconfig.database);



function getAllReport() {
  return connection.queryAsync('SELECT * FROM report');
}

function getReport(id) {
  return connection.queryAsync('SELECT * FROM report WHERE id = ?', [id]);
}

function putReport(req) {
  try {
    connection.queryAsync("INSERT INTO `advocate`.`report` (`message`, `image`, `reporterId`) VALUES (?, ?, ?);", [req.body.message,req.body.image,req.params.id ]);
    return "Insert Successful";
  }
  catch (ex){
    console.log(ex);
    throw ex;
  }
}

module.exports.getAll = function () {
  var results = async (function () {
    return await ( getAllReport());
  });
  var myResult = await(results()
    .then (function (result) {return result;})
    .catch(function (err) { console.log('Something went wrong: ' + err); }));
  return {status: 200, body: myResult};
};


module.exports.get = function (req) {
  var results = async (function () {
    return await ( getReport(req.params.id));
  });
  var myResult = await(results()
    .then (function (result) {return result;})
    .catch(function (err) { console.log('Something went wrong: ' + err); }));
  return {status: 200, body: myResult};
};

module.exports.put = function (req) {
  var results = async (function () {
    return await ( putReport(req));
  });
  var myResult = await(results()
    .then (function (result) {return result;})
    .catch(function (err) { console.log('Something went wrong: ' + err); }));
  return {status: 200, body: myResult};
};