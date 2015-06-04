import registerSuite = require('intern!object');
import assert = require('intern/chai!assert');
import * as crypto from 'src/crypto';

type Suite = { [ key: string ]: any };

function addTests(suite: Suite, algorithm: string, input: string, expected: number[]) {
	const hasher = crypto.getHash(algorithm);
	suite[algorithm] = {
		direct() {
			return hasher(input).then(function (result) {
				assert.deepEqual(toArray(result), expected);
			});
		},

		stream() {
			const hashObject = hasher.create();
			hashObject.write(input);
			hashObject.close();
			return hashObject.digest.then(function (result) {
				assert.deepEqual(toArray(result), expected);
			});
		}
	}
}

function toArray(buffer: crypto.Data): number[] {
	return Array.prototype.slice.call(buffer);
}

const suite: Suite = {
	name: 'hash'
}

addTests(suite, 'md5', 'The rain in Spain falls mainly on the plain.', [
	0x39, 0x48, 0x71, 0x6D, 0x56, 0x75, 0x32, 0xD9,
	0xAE, 0xE3, 0x3C, 0x7D, 0x2F, 0x34, 0xB9, 0x70
]);
addTests(suite, 'sha1', 'abc', [
	0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
	0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
	0x9C, 0xD0, 0xD8, 0x9D
]);
addTests(suite, 'sha256', 'abc', [
	0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
	0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
	0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
	0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
]);

registerSuite(suite);
