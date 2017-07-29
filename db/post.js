var dbconfig = require('../config/database');
var mysql = require('mysql');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var Promise = require('bluebird');

var connection =  Promise.promisifyAll(mysql.createConnection(dbconfig.connection));

connection.query('USE ' + dbconfig.database);

function getLatestPost(limit) {
    if (!limit) {
        limit = 10;
    }
    return connection.queryAsync('SELECT * FROM report ORDER BY id DESC limit ?', [limit]);
}

// TODO: update this function to insert a new report
function insertUser(facebookId, role) {
    if (role === undefined) {
         role = ROLE_USER;
    }
    try {
        connection.queryAsync( 
            "INSERT INTO `advocate`.`user` (`facebookId`, `role`) VALUES (?, ?);", 
            [facebookId, role]
        );
        return "Insert Successful";

    } catch (ex){
        console.log(ex);
        throw ex;
    }
}

module.exports.getLatestPost = getLatestPost;