const jwt = require('jsonwebtoken');
const randomstring = require('randomstring');
const bcrypt = require('bcrypt');
const moment = require('moment');
const { logger } = require('../utils/logger');
const { checkRequiredParameters, srcFileErrorHandler } = require('../utils/srcFile');
const { sendEmailText } = require('../utils/email');
const db = require('../utils/db');
const { addUserVerificationCode, verifyUserVerificationCode, deleteUserVerificationCode } = require('./verificationCodes');
const { getUserById, getUserByEmail, getUserByUsername } = require('./userInternalSrc');
const { isProfaneBulk } = require('../utils/stringTools');
const fileSrc = require('./fileSrc');

/**
 * @function deleteAccount
 * @summary Delete user account
 * @param {number} userId User's id
 * @param {string} password User's password
 * @param {object} user User object from token
 * @returns {object} deleteAccountStatus
 * @throws {object} errorCodeAndMsg
 */
const deleteAccount = async function deleteAccount(userId, password, user) {
  try {
    if (!userId || !password) throw { code: 400, message: 'Missing required variable(s)' };

    if (userId !== user.id) throw { code: 403, message: 'Operation not allowed' };

    // Get user information from database and check if it matches
    const userDb = await getUserById(userId);

    if (userDb && userDb.id == userId && password && password !== 'null' && userDb.password !== 'null' && await bcrypt.compare(password, userDb.password)) {
      await db.query('delete from users where id=$1', [userId], 'delete user account');

      return { message: 'Deleted user account successfully' };
    } else throw { code: 401, message: 'Please check email and password' };
  } catch (error) {
    console.log(error);
    srcFileErrorHandler(error, 'Could not delete user account');
  }
};

/**
 * @function updateAccountInformation
 * @summary Update user's account information
 * @param {string} username New user's username
 * @param {string} email New user's email
 * @param {string} fullName New user's fullName
 * @param {string} mobile New user's mobile
 * @param {object} user User object from token
 * @returns {object} updateAccountStatus
 * @throws {object} errorCodeAndMsg
 */
const updateAccountInformation = async function updateAccountInformation(username, email, fullName, mobile, user) {
  try {
    // Check email pattern
    if (!email.match(/^[a-zA-Z0-9.!#$%&’*+=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/gm)) throw { code: 400, message: 'Invalid email pattern' };

    // Check username pattern
    if (!username.match(/^(?=[a-zA-Z0-9._]{2,30}$)(?!.*[_.]{2})[^_.].*[^_.]$/gm)) throw { code: 400, message: 'Username can only be letters and numbers' };

    // Check isProfane information
    if (await isProfaneBulk([username, email, fullName, mobile])) throw { code: 400, message: 'Could not pass profane check to create user' };

    let count = 1;
    let updateString = 'update users set(';
    const updateArray = [];

    if (username) updateString = `${updateString}username,`;
    if (email) updateString = `${updateString}email,`;
    if (fullName) updateString = `${updateString}fullname,`;
    if (mobile) updateString = `${updateString}mobile,`;

    updateString = updateString.substring(0, updateString.length - 1);

    updateString = `${updateString})=(`;

    if (username) {
      updateString = `${updateString}$${count},`;
      count += 1;
      updateArray.push(username.trim());
    }
    if (email) {
      updateString = `${updateString}$${count},`;
      count += 1;
      updateArray.push(email.trim());
    }
    if (fullName) {
      updateString = `${updateString}$${count},`;
      count += 1;
      updateArray.push(fullName.trim());
    }
    if (mobile) {
      updateString = `${updateString}$${count},`;
      count += 1;
      updateArray.push(mobile.trim());
    }

    updateString = updateString.substring(0, updateString.length - 1);

    updateString = `${updateString}) where id=$${count} returning id`;
    updateArray.push(user.id);

    const [dbUser] = await db.query(updateString, updateArray, 'update user information');

    return { 'message': 'Updated user account successfully', id: dbUser.id };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not update user account');
  }
};

/**
 * @function getAccountAvatarByToken
 * @summary Get user account avatar url from database by token
 * @param {object} user User object from token
 * @returns {object} avatarUrl
 * @throws {object} errorCodeAndMsg
 */
const getAccountAvatarByToken = async function getAccountAvatarByToken(user) {
  try {
    // Get user information from database and check if it matches
    const [userDb] = await db.query('select avatar_url from users where id=$1', [user.id], 'Get user avatar_url from db');

    return ({ avatarUrl: userDb.avatar_url || '' });
  } catch (error) {
    srcFileErrorHandler(error, 'Could not get user account avatar url');
  }
};

/**
 * @function updateAccountAvatar
 * @summary Update user's profile picture
 * @param {object} req Http request
 * @param {object} user User information
 * @returns {object} updateAvatarResults
 * @throws {object} errorCodeAndMsg
 */
const updateAccountAvatar = async function updateAccountAvatar(req, user) {
  let fileUrl = '';
  try {
    // Upload user's profile picture locally
    const uploadFileResults = await fileSrc.uploadAvatarLocally(req);
    fileUrl = uploadFileResults.fileUrl ? uploadFileResults.fileUrl : '';

    // Check if the user already have an avatar then delete it
    const [dbUserExistingAvatar] = await db.query('select avatar_url from users where id=$1', [user.id], 'Get existing user avatar_url');

    if (dbUserExistingAvatar.avatar_url) fileSrc.deleteAvatarLocalByUrl(dbUserExistingAvatar.avatar_url);

    // Update user with new avatar url
    const [dbUser] = await db.query('update users set avatar_url=$1 where id=$2 returning id', [fileUrl, user.id], 'Update user avatar_url');

    if (dbUser.id) return { message: 'Account avatar updated successfully', avatarUrl: fileUrl };
    else throw { code: 500, message: 'Could not update account avatar' };
  } catch (error) {
    if (fileUrl) fileSrc.deleteAvatarLocalByUrl(fileUrl);
    srcFileErrorHandler(error, 'Could not update user account avatar');
  }
};

/**
 * @function getAccountInformationByToken
 * @summary Get user account information from database by user id
 * @param {object} user User object from token
 * @returns {object} userInformation
 * @throws {object} errorCodeAndMsg
 */
const getAccountInformationByToken = async function getAccountInformationByToken(user) {
  try {
    // Get user information from database and check if it matches
    const [userDb] = await db.query('select id, email, username, fullName, mobile, avatar_url from users where id=$1', [user.id], 'Get user information from db');

    if (userDb) return (userDb);
    else throw { code: 404, message: 'Could not get user account information by token' };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not get user account information by token');
  }
};

const requestResetPassword = async function requestResetPassword() {
  return 'not yet implemented';
};

const updateExistingPassword = async function updateExistingPassword() {
  return 'not yet implemented';
};

module.exports = {
  deleteAccount,
  updateAccountInformation,
  getAccountAvatarByToken,
  updateAccountAvatar,
  getAccountInformationByToken
};
