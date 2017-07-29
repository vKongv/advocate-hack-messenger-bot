var dbconfig = require('../config/database');
var mysql = require('mysql');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var Promise = require('bluebird');
var user = require('./user');

var connection =  Promise.promisifyAll(mysql.createConnection(dbconfig.connection));

connection.query('USE ' + dbconfig.database);

function getLatestPost(limit) {
    if (!limit) {
        limit = 10;
    }
    return connection.queryAsync('SELECT * FROM post ORDER BY id DESC limit ?', [limit]);
}

function getPostDetails(postId) {
    return connection.queryAsync('SELECT * FROM post WHERE id = ?', [postId]);    
}

var insertPost = async (function (userId) {
    try {
        var postInserted = await(connection.queryAsync( 
            "INSERT INTO `advocate`.`post` (`userId`) VALUES (?);", 
            [userId]
        ));
        user.updateUserIsPosting(userId, postInserted.insertId);
        return "Insert Successful";

    } catch (ex){
        console.log(ex);
        throw ex;
    }
});

function updatePostTitle (postId, title) {
    try {
        connection.queryAsync( 
            "UPDATE `advocate`.`post` SET `title` = ? WHERE `id` = ?",
            [title, postId]
        );
        return "Update Successful";
    } catch (ex){
        console.log(ex);
        throw ex;
    }
}

function updatePostLink (postId, link) {
    try {
        connection.queryAsync( 
            "UPDATE `advocate`.`post` SET `link` = ? WHERE `id` = ?",
            [link, postId]
        );
        return "Update Successful";
    } catch (ex){
        console.log(ex);
        throw ex;
    }
}

function updatePostDescription (postId, description) {
    try {
        connection.queryAsync( 
            "UPDATE `advocate`.`post` SET `description` = ? WHERE `id` = ?",
            [description, postId]
        );
        return "Update Successful";
    } catch (ex){
        console.log(ex);
        throw ex;
    }
}

function updatePostImage (postId, imageUrl) {
    try {
        connection.queryAsync( 
            "UPDATE `advocate`.`post` SET `imageUrl` = ? WHERE `id` = ?",
            [imageUrl, postId]
        );
        return "Update Successful";
    } catch (ex){
        console.log(ex);
        throw ex;
    }
}

module.exports.getLatestPost = getLatestPost;
module.exports.getPostDetails = getPostDetails;
module.exports.insertPost = insertPost;
module.exports.updatePostTitle = updatePostTitle;
module.exports.updatePostLink = updatePostLink;
module.exports.updatePostDescription = updatePostDescription;
module.exports.updatePostImage = updatePostImage;