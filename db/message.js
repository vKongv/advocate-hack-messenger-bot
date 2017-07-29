var dbconfig = require('../config/database');
var mysql = require('mysql');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var Promise = require('bluebird');
var connection =  Promise.promisifyAll(mysql.createConnection(dbconfig.connection));
connection.query('USE ' + dbconfig.database);

var TYPE_TEXT = 'TEXT';
var TYPE_IMAGE = 'IMAGE';

function getLatestUserReportMessage (reporterId) {
    return connection.queryAsync('SELECT message.* FROM message INNER JOIN report ON message.reportId = report.id AND message.reportId = (SELECT id FROM report WHERE reporterId = ? ORDER BY id DESC LIMIT 1)',
        [reporterId]);
}

function insertMessage(reportId, text, type) {
    if (!type) {
        type = TYPE_TEXT;
    }
  try {
    connection.queryAsync("INSERT INTO `advocate`.`message` (`text`, `type`, `reportId`) VALUES (?, ?, ?);",
        [text,type,reportId]);
    return "Insert Successful";
  }
  catch (ex){
    console.log(ex);
    throw ex;
  }
}

module.exports.TYPE_TEXT = TYPE_TEXT;
module.exports.TYPE_IMAGE = TYPE_IMAGE;
module.exports.getLatestUserReportMessage = getLatestUserReportMessage;