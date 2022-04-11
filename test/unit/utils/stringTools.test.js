const { expect } = require('chai');
const main = require('../../../utils/stringTools');

describe('stringTools.js', function () {

  describe('titleCase', function () {
    it('should return string in title case', function () {
      try {
        const results = main.titleCase('hello world!');
        expect(results).equals('Hello World!');
      } catch (error) {
        expect(error).to.be.null;
      }
    });
    it('should return original string if there is an error', function () {
      try {
        const results = main.titleCase([]);
        expect(results).to.deep.equal([]);
      } catch (error) {
        expect(error).to.be.null;
      }
    });
  });
});
