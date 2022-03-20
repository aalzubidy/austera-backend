const { logger } = require('../utils/logger');
const { srcFileErrorHandler } = require('../utils/srcFile');
const packageJSONFile = require('../package.json');

/**
 * @function getSystemVersion
 * @summary Get system version
 * @returns {object} systemVersionResults
 * @throws {object} errorCodeAndMsg
 */
const getSystemVersion = async function getSystemVersion() {
  try {
    const version = packageJSONFile['version'];
    logger.debug({ label: 'system version response', results: version });

    if (version) {
      return version;
    } else return false;
  } catch (error) {
    srcFileErrorHandler(error, 'could not get system version');
  }
};

/**
 * @function systemPing
 * @summary Ping system and return success
 * @returns {string} systemPingResults
 */
const systemPing = async function systemPing() {
  return 'Hi! Successful ping!';
};

module.exports = {
  getSystemVersion,
  systemPing
};
