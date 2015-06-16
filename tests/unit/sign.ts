import registerSuite = require('intern!object');
import assert = require('intern/chai!assert');
import * as crypto from 'src/crypto';
import { ascii, base64, hex, utf8 } from 'dojo-core/encoding';

type Suite = { [ key: string ]: any };

function addTests(suite: Suite, algorithm: string, key: crypto.Key, input: string, expected: number[]) {
	let sign: crypto.SignFunction;

	suite[algorithm + '-' + key.algorithm] = {
		direct() {
			// clear the provider so we can try out the deferred #sign
			crypto.setProvider(undefined);
			sign = crypto.getSign(algorithm);
			return sign(key, input).then(function (result) {
				assert.deepEqual(toArray(result), expected);
			});
		},

		encoded: {
			utf8() {
				return sign(key, input, utf8).then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			},

			ascii() {
				return sign(key, input, ascii).then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			},

			base64() {
				const inputBytes = utf8.encode(input);
				const input64 = base64.decode(inputBytes);
				return sign(key, input64, base64).then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			},

			hex() {
				const inputBytes = utf8.encode(input);
				const inputHex = hex.decode(inputBytes);
				return sign(key, inputHex, hex).then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			}
		},

		stream: {
			'full run': {
				direct() {
					// Clear the provider so we can try out the deferred #create
					crypto.setProvider(undefined);
					sign = crypto.getSign(algorithm);

					const signer = sign.create(key);
					signer.write(input);
					signer.close();
					return signer.signature.then(function (result) {
						assert.deepEqual(toArray(result), expected);
					});
				},

				encoded() {
					const signer = sign.create(key, utf8);
					signer.write(input);
					signer.close();
					return signer.signature.then(function (result) {
						assert.deepEqual(toArray(result), expected);
					});
				},

				'after direct sign'() {
					// Get a hash, use it, then call create to test the `realHash` branch
					sign = crypto.getSign(algorithm);
					return sign(key, '').then(function () {
						const signer = sign.create(key, utf8);
						signer.write(input);
						signer.close();
						return signer.signature.then(function (result) {
							assert.deepEqual(toArray(result), expected);
						});
					});
				}
			},

			start() {
				// Reset the provider so we'll call the wrapper's start
				crypto.setProvider(undefined);
				sign = crypto.getSign(algorithm);

				// Just check that it doesn't throw
				const signer = sign.create(key);
				signer.start(function () {});
			},

			aborted() {
				// Reset the provider so we'll call the wrapper's start
				crypto.setProvider(undefined);
				sign = crypto.getSign(algorithm);

				const signer = sign.create(key);
				signer.write(input);
				signer.abort(new Error('canceled'));
				return signer.signature.then(
					function (result) {
						assert(false, 'Signature should have rejected');
					}, function (reason) {
						assert.strictEqual(reason.message, 'canceled');
					}
				).then(function () {
					// Call abort a second time to verify that it doesn't throw
					signer.abort(new Error('ignored'));
				}).then(function () {
					// Call after abort to verify that it doesn't throw
					signer.close();
				}).then(function () {
					// Call after abort to verify that it doesn't throw
					signer.write('');
				});
			}
		}
	};
}

function toArray(buffer: crypto.Data): number[] {
	return Array.prototype.slice.call(buffer);
}

const suite: Suite = {
	name: 'sign',

	'invalid algorithm before load'() {
		crypto.setProvider(undefined);
		assert.throws(function () {
			crypto.getSign('foo');
		}, /^invalid algorithm/);
	}
};

let key: crypto.Key = { algorithm: 'sha256', data: 'Jefe' };
const data = 'what do ya want for nothing?';

addTests(suite, 'hmac', key, data, [
	0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E,
	0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xC7,
	0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83,
	0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC, 0x38, 0x43
]);

key = { algorithm: 'sha1', data: 'Jefe' };
addTests(suite, 'hmac', key, data, [
	0xEF, 0xFC, 0xDF, 0x6A, 0xE5, 0xEB, 0x2F, 0xA2,
	0xD2, 0x74, 0x16, 0xD5, 0xF1, 0x84, 0xDF, 0x9C,
	0x25, 0x9A, 0x7C, 0x79
]);

key = { algorithm: 'md5', data: 'Jefe' };
addTests(suite, 'hmac', key, data, [
	0x75, 0x0C, 0x78, 0x3E, 0x6A, 0xB0, 0xB5, 0x03,
	0xEA, 0xA8, 0x6E, 0x31, 0x0A, 0x5D, 0xB7, 0x38
]);

suite['invalid algorithm after load'] = function () {
	assert.throws(function () {
		crypto.getSign('foo');
	}, /^invalid algorithm/);
};

registerSuite(suite);
