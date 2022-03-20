const express = require('express');
const router = express.Router();
const { callSrcFileSkipVerify } = require('../utils/srcFile');
const systemSrc = require('../src/systemSrc');

/**
 * @summary Get system version
 */
router.get('/system/version', async (req, res) => {
  callSrcFileSkipVerify(systemSrc, 'getSystemVersion', [], req, res);
});

/**
 * @summary Get system ping
 */
router.get('/system/ping', async (req, res) => {
  callSrcFileSkipVerify(systemSrc, 'systemPing', [], req, res);
});

module.exports = router;
