const express = require('express');
const router = express.Router();
const userAccountSrc = require('../src/userAccountSrc');
const { callSrcFile, callSrcFileSkipVerify } = require('../utils/srcFileAuthorization');

/**
 * @summary Delete a user
 */
router.delete('/users', async (req, res) => {
  callSrcFile(userAccountSrc, 'deleteUser', [req], req, res);
});

/**
 * @summary Update user's account information
 */
router.patch('/users', async (req, res) => {
  const { username, email, firstName, lastName, mobile } = req.body;
  callSrcFile(userAccountSrc, 'updateUserInformation', [username, email, firstName, lastName, mobile], req, res);
});

module.exports = router;
