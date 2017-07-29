var dbconfig = require('../config/database');
var mysql = require('mysql');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var Promise = require('bluebird');
var connection =  Promise.promisifyAll(mysql.createConnection(dbconfig.connection));
connection.query('USE ' + dbconfig.database);

var REPORT_TYPE_SEX = 'SEX';
var REPORT_TYPE_DOMESTIC = 'DOMESTIC';
var REPORT_TYPE_OTHERS = 'OTHERS';
var REPORT_TYPE_EVENT = 'EVENT';
var REPORT_TYPE_NEWS = 'NEWS';

function getAllReport() {
  return connection.queryAsync('SELECT * FROM report');
}

function getReport(id) {
  return connection.queryAsync('SELECT * FROM report WHERE id = ?', [id]);
}

function insertReport(reporterId, type) {
    try {
        return connection.queryAsync( 
            "INSERT INTO `advocate`.`report` (`reporterId`, `type`) VALUES (?, ?);", 
            [reporterId, type]
        );
        // return "Insert Successful";

    } catch (ex){
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

module.exports.REPORT_TYPE_SEX = REPORT_TYPE_SEX;
module.exports.REPORT_TYPE_DOMESTIC = REPORT_TYPE_DOMESTIC;
module.exports.REPORT_TYPE_OTHERS = REPORT_TYPE_OTHERS;
module.exports.REPORT_TYPE_EVENT = REPORT_TYPE_EVENT;
module.exports.REPORT_TYPE_NEWS = REPORT_TYPE_NEWS;
module.exports.insertReport = insertReport;