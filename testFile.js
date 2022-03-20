const systemSrc = require('./src/systemSrc');

const test = async (fileSrc, funName) => {
  console.log(await fileSrc[funName].apply(this, []));
}

test(systemSrc, 'systemPing');
