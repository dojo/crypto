import registerSuite = require('intern!object');
import assert = require('intern/chai!assert');
import * as crypto from 'src/crypto';
import { ascii, base64, hex, utf8 } from 'dojo-core/encoding';

type Suite = { [ key: string ]: any };

function addTests(suite: Suite, algorithm: string, input: string, expected: number[]) {
	let hash: crypto.HashFunction;

	suite[algorithm] = {
		direct() {
			// clear the provider so we can try out the deferred #hash
			crypto.setProvider(undefined);
			hash = crypto.getHash(algorithm);
			return hash(input).then(function (result) {
				assert.deepEqual(toArray(result), expected);
			});
		},

		encoded: {
			utf8() {
				return hash(input, utf8).then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			},

			ascii() {
				return hash(input, ascii).then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			},

			base64() {
				const inputBytes = utf8.encode(input);
				const input64 = base64.decode(inputBytes);
				return hash(input64, base64).then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			},

			hex() {
				const inputBytes = utf8.encode(input);
				const inputHex = hex.decode(inputBytes);
				return hash(inputHex, hex).then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			}
		},

		stream: {
			'full run': {
				direct() {
					// Clear the provider so we can try out the deferred #create
					crypto.setProvider(undefined);
					hash = crypto.getHash(algorithm);

					const hasher = hash.create();
					hasher.write(input);
					hasher.close();
					return hasher.digest.then(function (result) {
						assert.deepEqual(toArray(result), expected);
					});
				},

				encoded() {
					const hasher = hash.create(utf8);
					hasher.write(input);
					hasher.close();
					return hasher.digest.then(function (result) {
						assert.deepEqual(toArray(result), expected);
					});
				},

				'after direct hash'() {
					// Get a hash, use it, then call create to test the `realHash` branch
					hash = crypto.getHash(algorithm);
					return hash('').then(function () {
						const hasher = hash.create(utf8);
						hasher.write(input);
						hasher.close();
						return hasher.digest.then(function (result) {
							assert.deepEqual(toArray(result), expected);
						});
					});
				}
			},

			start() {
				// Reset the provider so we'll call the wrapper's start
				crypto.setProvider(undefined);
				hash = crypto.getHash(algorithm);

				// Just check that it doesn't throw
				const hasher = hash.create();
				hasher.start(function () {});
			},

			aborted() {
				// Reset the provider so we'll call the wrapper's abort
				crypto.setProvider(undefined);
				hash = crypto.getHash(algorithm);

				const hasher = hash.create();
				hasher.abort(new Error('canceled'));
				return hasher.digest.then(
					function (result) {
						assert(false, 'hashature should have rejected');
					}, function (reason) {
						assert.strictEqual(reason.message, 'canceled');
					}
				).then(function () {
					// Call abort a second time to verify that it doesn't throw
					hasher.abort(new Error('ignored'));
				}).then(function () {
					// Call after abort to verify that it doesn't throw
					hasher.close();
				}).then(function () {
					// Call after abort to verify that it doesn't throw
					hasher.write('');
				});
			}
		}
	};
}

function toArray(buffer: crypto.Data): number[] {
	return Array.prototype.slice.call(buffer);
}

const suite: Suite = {
	name: 'hash',

	'invalid algorithm'() {
		crypto.setProvider(undefined);
		assert.throws(function () {
			crypto.getHash('foo');
		}, /^invalid algorithm/);
	}
};

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
