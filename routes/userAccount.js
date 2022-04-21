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

module.exports = router;
