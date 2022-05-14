const jwt = require('jsonwebtoken');
const randomstring = require('randomstring');
const bcrypt = require('bcrypt');
const moment = require('moment');
const { logger } = require('../utils/logger');
const { srcFileErrorHandler } = require('../utils/srcFile');
const { sendEmailText } = require('../utils/email');
const db = require('../utils/db');
const { addUserVerificationCode, verifyUserVerificationCode, deleteUserVerificationCode } = require('./verificationCodes');

/**
 * @function isUsernameAvailable
 * @summary Check if username already in the database
 * @param {string} username - Username to check
 * @returns {object} checkUsernameResults
 * @throws {object} errorCodeAndMsg
 */
const isUsernameAvailable = async function isUsernameAvailable(username) {
  try {
    if (!username) throw { code: 400, message: 'Missing required variable(s): username' };

    const [dbUser] = await db.query('select username from users where username=$1', [username], 'check existing username');

    return !dbUser?.username;
  } catch (error) {
    srcFileErrorHandler(error, 'Could not check for existing username');
  }
};

module.exports = {
  isUsernameAvailable
};
