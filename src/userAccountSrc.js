const jwt = require('jsonwebtoken');
const randomstring = require('randomstring');
const bcrypt = require('bcrypt');
const moment = require('moment');
const { logger } = require('../utils/logger');
const { checkRequiredParameters, srcFileErrorHandler } = require('../utils/srcFile');
const { sendEmailText } = require('../utils/email');
const db = require('../utils/db');
const { addUserVerificationCode, verifyUserVerificationCode, deleteUserVerificationCode } = require('./userVerificationSrc');
const { getUserById, getUserByEmail, getUserByUsername } = require('./userSrc');

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

      // Check the user again
      const userDbDoubleCheck = await getUserById(userId);

      if (!userDbDoubleCheck) return { message: 'Deleted user successfully' };
      else throw { code: 500, message: 'Could not delete user from db' };
    } else throw { code: 401, message: 'Please check email and password' };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not delete user');
  }
};

const updateUserInformation = async function updateUserInformation() {
  return 'not yet implemented';
};

const updateUserAvatar = async function updateUserAvatar() {
  return 'not yet implemented';
};

const requestResetPassword = async function requestResetPassword() {
  return 'not yet implemented';
};

const updateExistingPassword = async function updateExistingPassword() {
  return 'not yet implemented';
};

module.exports = {
  deleteUser
};
