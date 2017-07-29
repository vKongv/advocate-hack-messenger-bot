var dbconfig = require('../config/database');
var mysql = require('mysql');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var Promise = require('bluebird');

var connection =  Promise.promisifyAll(mysql.createConnection(dbconfig.connection));

connection.query('USE ' + dbconfig.database);

var ROLE_USER = 'USER';
var ROLE_MODERATOR = 'MODERATOR';
var ROLE_NGO = 'NGO';

function getUser(id) {
    if ( id ) {
        return connection.queryAsync('SELECT * FROM user WHERE facebookId = ?', [id]);
    } else {
        return connection.queryAsync('SELECT * FROM user');
    }
}

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

function updateUserState(facebookId, reportId) {
    try {
        connection.queryAsync( 
            "UPDATE `advocate`.`user` SET `isReporting` = ? WHERE `facebookId` = ?",
            [reportId, facebookId]
        );
        return "Update Successful";

    } catch (ex){
        console.log(ex);
        throw ex;
    }
}

function getModeratorUsers(){
    return connection.queryAsync('SELECT * FROM user WHERE role = ?', [ROLE_MODERATOR]);
}

module.exports.ROLE_USER = ROLE_USER;
module.exports.ROLE_MODERATOR = ROLE_MODERATOR;
module.exports.ROLE_NGO = ROLE_NGO;
module.exports.insertUser = insertUser;
module.exports.getUser = getUser;
module.exports.updateUserState = updateUserState;
module.exports.getModeratorUsers = getModeratorUsers;