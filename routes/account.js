const express = require('express');
const router = express.Router();
const accountSrc = require('../src/accountSrc');
const { callSrcFile, callSrcFileSkipVerify } = require('../utils/srcFileAuthorization');

/**
 * @summary Get user's information from database
 */
router.get('/account', async (req, res) => {
  callSrcFile(accountSrc, 'getAccountInformationByToken', [], req, res);
});

/**
 * @summary Delete an account
 */
router.delete('/account', async (req, res) => {
  const { userId, password } = req.body;
  callSrcFile(accountSrc, 'deleteAccount', [userId, password], req, res);
});

/**
 * @summary Update user's account information
 */
router.patch('/account', async (req, res) => {
  const { username, email, fullname, mobile } = req.body;
  callSrcFile(accountSrc, 'updateAccountInformation', [username, email, fullname, mobile], req, res);
});

/**
 * @summary Get user's account profile picture url
 */
router.get('/account/avatar', async (req, res) => {
  callSrcFile(accountSrc, 'getAccountAvatarByToken', [], req, res);
});

/**
 * @summary Update user's profile picture
 */
router.patch('/account/avatar', async (req, res) => {
  callSrcFile(accountSrc, 'updateAccountAvatar', [req], req, res);
});

module.exports = router;
