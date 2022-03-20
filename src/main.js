const { logger } = require('../utils/logger');

const someFunction = async function someFunction() {
  try {
    logger.info('some function');
    return {};
  } catch (error) {
    throw new Error(error);
  }
};

module.exports = {
  someFunction
};
