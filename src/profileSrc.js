const jwt = require('jsonwebtoken');
const randomstring = require('randomstring');
const bcrypt = require('bcrypt');
const moment = require('moment');
const { logger } = require('../utils/logger');
const { checkRequiredParameters, srcFileErrorHandler } = require('../utils/srcFile');
const { sendEmailText } = require('../utils/email');
const db = require('../utils/db');
const { addUserVerificationCode, verifyUserVerificationCode, deleteUserVerificationCode } = require('./verificationCodes');
const { getUserById, getUserByEmail, getUserByUsername } = require('./userSrc');
const { isProfaneBulk } = require('../utils/stringTools');
const fileSrc = require('./fileSrc');

/**
 * @function deleteUser
 * @summary Delete user from system
 * @param {*} req http request contains userId, and password
 * @param {object} user User object from token
 * @returns {object} deleteAccountStatus
 * @throws {object} errorCodeAndMsg
 */
const deleteUser = async function deleteUser(req, user) {
  try {
    const { userId, password } = req.body;

    await checkRequiredParameters({ userId, password });

    if (userId !== user.id) throw { code: 403, message: 'Operation not allowed' };

    // Get user information from database and check if it matches
    const userDb = await getUserById(userId);

    if (userDb && userDb.id == userId && password && password !== 'null' && userDb.password !== 'null' && await bcrypt.compare(password, userDb.password)) {
      await db.query('delete from users where id=$1', [userId], 'delete user');

      return { message: 'Deleted user successfully' };
    } else throw { code: 401, message: 'Please check email and password' };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not delete user');
  }
};

/**
 * @function updateUserInformation
 * @summary Update user's account information
 * @param {string} username New user's username
 * @param {string} email New user's email
 * @param {string} firstName New user's firstName
 * @param {string} lastName New user's lastName
 * @param {string} mobile New user's mobile
 * @param {object} user User object from token
 * @returns {object} updateAccountStatus
 * @throws {object} errorCodeAndMsg
 */
const updateUserInformation = async function updateUserInformation(username, email, firstName, lastName, mobile, user) {
  try {
    // Check isProfane information
    if (isProfaneBulk([username, email, firstName, lastName, mobile])) throw { code: 400, message: 'Could not check words in update user information' };

    let count = 1;
    let updateString = 'update users set(';
    const updateArray = [];

    if (username) updateString = `${updateString}username,`;
    if (email) updateString = `${updateString}email,`;
    if (firstName) updateString = `${updateString}firstname,`;
    if (lastName) updateString = `${updateString}lastname,`;
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
    if (firstName) {
      updateString = `${updateString}$${count},`;
      count += 1;
      updateArray.push(firstName.trim());
    }
    if (lastName) {
      updateString = `${updateString}$${count},`;
      count += 1;
      updateArray.push(lastName.trim());
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

    return { 'message': 'Updated user successfully', id: dbUser.id };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not update user');
  }
};

/**
 * @function getUserAvatar
 * @summary Get user avatar url from database
 * @param {object} user User object from token
 * @returns {object} avatarUrl
 * @throws {object} errorCodeAndMsg
 */
const getUserAvatar = async function getUserAvatar(user) {
  try {
    // Get user information from database and check if it matches
    const [userDb] = await db.query('select avatar_url from users where id=$1', [user.id], 'Get user avatar_url from db');

    return (userDb.avatar_url || '');
  } catch (error) {
    srcFileErrorHandler(error, 'Could not get user avatar_url');
  }
};

/**
 * @function updateUserAvatar
 * @summary Update user's profile picture
 * @param {object} req Http request
 * @param {object} user User information
 * @returns {object} updateAvatarResults
 * @throws {object} errorCodeAndMsg
 */
const updateUserAvatar = async function updateUserAvatar(req, user) {
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

    if (dbUser.id) return { message: 'Profile picture updated successfully' };
    else throw { code: 500, message: 'Could not update profile picture' };
  } catch (error) {
    if (fileUrl) fileSrc.deleteAvatarLocalByUrl(fileUrl);
    srcFileErrorHandler(error, 'Could not update user profile picture');
  }
};

const requestResetPassword = async function requestResetPassword() {
  return 'not yet implemented';
};

const updateExistingPassword = async function updateExistingPassword() {
  return 'not yet implemented';
};

module.exports = {
  deleteUser,
  updateUserInformation,
  getUserAvatar,
  updateUserAvatar
};
