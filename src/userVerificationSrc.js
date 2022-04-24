const moment = require('moment');
const db = require('../utils/db');

/**
 * @function addUserVerificationCode
 * @summary Add a user's verification code
 * @param {string} userId User's id
 * @param {string} verificationCode User's verification code
 * @param {string} codeType Type of code e.g. new user, password reset, etc
 * @returns {object} addCodeResults
 * @throws {boolean} false
 */
const addUserVerificationCode = async function addUserVerificationCode(userId, verificationCode, codeType) {
  try {
    // Get today's date
    const createDate = moment().format('MM/DD/YYYY');

    // Add user's verificationCode in the database
    const [dbUser] = await db.query('insert into user_verifications(user_id, verification_code, code_type, create_date) values($1, $2, $3, $4) returning user_id', [userId, verificationCode, codeType, createDate], 'add user verification_code');

    if (dbUser && dbUser.user_id) return dbUser;
    else throw { code: 500, message: 'Could not add a verification code' };
  } catch (error) {
    throw { code: 500, message: 'Could not add a verification code into db' };
  }
};

/**
 * @function verifyUserVerificationCode
 * @summary Get a user's verification code
 * @param {string} userId User's id
 * @param {string} verificationCode User's verification code
 * @param {string} codeType Type of code e.g. new user, password reset, etc
 * @returns {object} verificationCodeResults
 * @throws {boolean} false
 */
const verifyUserVerificationCode = async function verifyUserVerificationCode(userId, verificationCode, codeType) {
  try {
    // Add user's verificationCode in the database
    const [dbUser] = await db.query('select user_id from user_verifications where user_id=$1 and verification_code=$2 and code_type=$3', [userId, verificationCode, codeType], 'get user verification_code');

    if (dbUser && dbUser.user_id) return dbUser;
    else throw { code: 500, message: 'Could not get a verification code' };
  } catch (error) {
    throw { code: 500, message: 'Could not get a verification code from db' };
  }
};

/**
 * @function deleteUserVerificationCode
 * @summary Delete a user's verification code
 * @param {string} userId User's id
 * @param {string} verificationCode User's verification code
 * @param {string} codeType Type of code e.g. new user, password reset, etc
 * @returns {object} deleteCodeResults
 * @throws {boolean} false
 */
const deleteUserVerificationCode = async function deleteUserVerificationCode(userId, verificationCode, codeType) {
  try {
    // Add user's verificationCode in the database
    return await db.query('delete from user_verifications where user_id=$1 and verification_code=$2 and code_type=$3', [userId, verificationCode, codeType], 'delete user verification_code');
  } catch (error) {
    throw { code: 500, message: 'Could not delete a verification code from db' };
  }
};

module.exports = {
  addUserVerificationCode,
  verifyUserVerificationCode,
  deleteUserVerificationCode
};
