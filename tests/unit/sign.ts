import registerSuite = require('intern!object');
import assert = require('intern/chai!assert');
import Promise from 'dojo-core/Promise';
import * as crypto from 'src/crypto';
import * as script from 'src/providers/script';
import { ascii, base64, hex, utf8 } from 'dojo-core/encoding';
import WritableStream, { Sink } from 'dojo-core/streams/WritableStream';
import has from 'src/has';

type AnyObject = { [ key: string ]: any };
type Suite = AnyObject;

interface TestData {
	algorithm: string
	input: string
	key: crypto.Key
	expected: number[]
}

function addProviderTests(
	suite: Suite,
	provider: string,
	setProvider: (provider: any) => void,
	getSign: (algorithm: string) => crypto.SignFunction,
	testData: TestData[]
) {
	testData.forEach(function (data: TestData) {
		let sign: crypto.SignFunction;
		const { algorithm, expected, input, key } = data;

		suite[`${provider} - ${algorithm} - ${key.algorithm}`] = {
			direct: {
				string() {
					// clear the provider so we can try out the deferred #sign
					setProvider(undefined);
					sign = getSign(algorithm);
					return sign(key, input).then(function (result) {
						assert.deepEqual(toArray(result), expected);
					});
				},

				binary() {
					const inputBytes = utf8.encode(input);
					return sign(key, inputBytes).then(function (result) {
						assert.deepEqual(toArray(result), expected);
					});
				}
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

			stream: (function () {
				function streamingWrite<T>(sink: Sink<T>, data: T): void {
					const stream = new WritableStream<T>(sink);
					stream.write(data);
					stream.close();
				}

				return {
					'full run': {
						direct() {
							// Clear the provider so we can try out the deferred #create
							setProvider(undefined);
							sign = getSign(algorithm);

							const signer = sign.create(key);
							streamingWrite(signer, input);
							return signer.signature.then(function (result) {
								assert.deepEqual(toArray(result), expected);
							});
						},

						encoded() {
							const signer = sign.create(key, utf8);
							streamingWrite(signer, input);
							return signer.signature.then(function (result) {
								assert.deepEqual(toArray(result), expected);
							});
						},

						binary() {
							const signer = sign.create(key);
							streamingWrite(signer, utf8.encode(input));
							return signer.signature.then(function (result) {
								assert.deepEqual(toArray(result), expected);
							});
						},

						'after direct sign'() {
							// Get a hash, use it, then call create to test the `realHash` branch
							sign = getSign(algorithm);
							return sign(key, '').then(function () {
								const signer = sign.create(key, utf8);
								streamingWrite(signer, input);
								return signer.signature.then(function (result) {
									assert.deepEqual(toArray(result), expected);
								});
							});
						}
					},

					aborted() {
						// Reset the provider so we'll call the wrapper's start
						setProvider(undefined);
						sign = getSign(algorithm);

						const signer = sign.create(key);
						const stream = new WritableStream<string>(signer);
						stream.write(input);
						stream.abort(new Error('canceled'));

						return signer.signature.then(
							function (result) {
								assert(false, 'Signature should have rejected');
							}, function (reason) {
								assert.strictEqual(reason.message, 'canceled');
							}
						).then(function () {
							// Call abort a second time to verify that it doesn't throw
							stream.abort(new Error('ignored'));
						}).then(function () {
							// Call after abort to verify that it doesn't throw
							stream.close();
						}).then(function () {
							// Call after abort to verify that it doesn't throw
							stream.write('');
						});
					}
				}
			})()
		};
	});
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
	},

	'bad provider': function () {
		const dfd = this.async();
		crypto.setProvider(new Promise(function (resolve, reject) {
			reject(new Error('bad'));
		}));
		const sign = crypto.getSign('hmac');
		const key = { algorithm: 'md5', data: '123' };
		const signer = sign.create(key);
		signer.signature.catch(dfd.callback(function () {}));
	},

	// Test SignerWrapper methods that don't get exercised by the regular provider tests
	wrapper: (function () {
		const key = { algorithm: 'md5', data: '123' };

		function wrapperTest(methodName: string, ...args: any[]) {
			let resolver: Function;
			crypto.setProvider(new Promise(function (resolve, reject) {
				resolver = resolve;
			}));

			const sign = crypto.getSign('hmac');
			const signer = sign.create(key);
			const promise = (<any> signer)[methodName].apply(signer, args);

			resolver({
				getSign: function () {
					const signFunc: any = function () {}
					signFunc.create = function () {
						var methods: any = {};
						methods[methodName] = function () {
							return Promise.resolve();
						};
						return methods;
					}
					return signFunc;
				}
			});

			return promise;
		}

		return {
			close: function () {
				return wrapperTest('close');
			},

			write: function () {
				return wrapperTest('write', 'abc');
			},
		};
	})()
};

const input = 'what do ya want for nothing?';

// Default provider tests

if (has('webcrypto') || has('host-node')) {
	const testData: TestData[] = [
		{
			algorithm: 'hmac',
			input: input,
			key: { algorithm: 'sha256', data: 'Jefe' },
			expected: [
				0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E,
				0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xC7,
				0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83,
				0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC, 0x38, 0x43
			]
		},
		{
			algorithm: 'hmac',
			input: input,
			key: { algorithm: 'sha1', data: 'Jefe' },
			expected: [
				0xEF, 0xFC, 0xDF, 0x6A, 0xE5, 0xEB, 0x2F, 0xA2,
				0xD2, 0x74, 0x16, 0xD5, 0xF1, 0x84, 0xDF, 0x9C,
				0x25, 0x9A, 0x7C, 0x79
			]
		},
		{
			algorithm: 'hmac',
			input: input,
			key: { algorithm: 'md5', data: 'Jefe' },
			expected: [
				0x75, 0x0C, 0x78, 0x3E, 0x6A, 0xB0, 0xB5, 0x03,
				0xEA, 0xA8, 0x6E, 0x31, 0x0A, 0x5D, 0xB7, 0x38
			]
		}
	];

	addProviderTests(suite, 'default', crypto.setProvider.bind(crypto), crypto.getSign.bind(crypto), testData);
}

// Script provider tests

const testData: TestData[] = [
	{
		algorithm: 'hmac',
		input: input,
		key: { algorithm: 'md5', data: 'Jefe' },
		expected: [
			0x75, 0x0C, 0x78, 0x3E, 0x6A, 0xB0, 0xB5, 0x03,
			0xEA, 0xA8, 0x6E, 0x31, 0x0A, 0x5D, 0xB7, 0x38
		]
	},
	{
		algorithm: 'hmac',
		input: input,
		key: { algorithm: 'sha256', data: 'Jefe' },
		expected: [
			0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E,
			0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xC7,
			0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83,
			0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC, 0x38, 0x43
		]
	}
];

addProviderTests(suite, 'script', () => null, script.getSign.bind(script), testData);

suite['invalid algorithm after load'] = function () {
	assert.throws(function () {
		crypto.getSign('foo');
	}, /^invalid algorithm/);
};

registerSuite(suite);
