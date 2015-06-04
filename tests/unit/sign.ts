import registerSuite = require('intern!object');
import assert = require('intern/chai!assert');
import * as crypto from 'src/crypto';

type Suite = { [ key: string ]: any };

function addTests(suite: Suite, algorithm: string, key: crypto.Key, input: string, expected: number[]) {
	const signingFunction = crypto.getSign(algorithm);
	suite[algorithm + '-' + key.algorithm] = {
		direct() {
			return signingFunction(key, input).then(function (result) {
				assert.deepEqual(toArray(result), expected);
			});
		},

		stream: {
			'full run'() {
				const signer = signingFunction.create(key);
				signer.write(input);
				signer.close();
				return signer.signature.then(function (result) {
					assert.deepEqual(toArray(result), expected);
				});
			},

			start() {
				// Just check that it doesn't throw
				const signer = signingFunction.create(key);
				signer.start(function () {});
			},

			aborted() {
				const signer = signingFunction.create(key);
				signer.write(input);
				signer.abort(new Error('canceled'));
				return signer.signature.then(function (result) {
					assert(false, 'Signature should have rejected');
				}, function (reason) {
					assert.strictEqual(reason.message, 'canceled');
				});
			}
		}
	}
}

function toArray(buffer: crypto.Data): number[] {
	return Array.prototype.slice.call(buffer);
}

const suite: Suite = {
	name: 'sign'
}

const key: crypto.Key = {
	algorithm: 'sha256',
	data: 'Jefe'
};
addTests(suite, 'hmac', key, 'what do ya want for nothing?', [
	0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E,
	0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xC7,
	0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83,
	0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC, 0x38, 0x43
]);

registerSuite(suite);
