/**
 * crypto
 *
 * Architecture
 * ------------
 *
 * The crypto API has two main functions: `getHash` and `getSign`. These functions return functions implementing the
 * HashFunction and SignFunction interfaces, respectively. HashFunctions and SignFunctions are what user code calls to
 * hash or sign data.
 *
 * Actual implementations are supplied by providers such as `providers/node.ts`. A provider is just a module exporting
 * the two API functions `getHash` and `getSign`. Since each provider implements the public API, they can be used
 * directly, although this should not generally be necessary.
 *
 * When user code calls this module's `getHash` function, the function immediately starts loading a provider and returns
 * a wrapper function implementing the HashFunction API. The wrapper will defer all calls until the provider loads. Once
 * the provider is loaded, the wrapper calls `getHash` on the provider to obtain a real HashFunction instance and
 * resolves any outstanding calls. Future calls on the wrapper are passed directly to the created HashFunction instance.
 *
 * When the HashFunction wrapper's `create` method is called, it returns a wrapped Hasher instance. Like the
 * HashFunction wrapper, the Hasher wrapper will defer calls until a provider is loaded and a real Hasher implementation
 * has been created, at which point all future calls to methods on the wrapper are passed directly to the real Hasher.
 *
 * The current provider may be requested with the `getProvider` function. Since the initial provider is loaded
 * asynchronously, this function returns a Promise<CryptoProvider>. The provider may be set using the `setProvider`
 * function, which accepts a CryptoProvider.
 */

import { Codec, ByteBuffer } from 'dojo-core/encoding';
import Promise from 'dojo-core/Promise';
import { Sink } from 'dojo-core/streams/WritableStream';
import has from './has';

declare const define: { amd: any };
declare const require: Function;

export type Data = string | ByteBuffer;

/**
 * Supported hash algorithms 
 */
const HASH_ALGORITHMS = {
	md5: true,
	sha1: true,
	sha256: true
}

/**
 * Supported signing algorithms 
 */
const SIGN_ALGORITHMS = {
	hmac: true
}

/**
 * An interface describing a cryptographic provider.
 */
export interface CryptoProvider {
	getHash(algorithm: string): HashFunction;
	getSign(algorithm: string): SignFunction;
}

/**
 * A function that can hash a chunk of data.
 */
export interface HashFunction {
	(data: ByteBuffer): Promise<ByteBuffer>;
	(data: string, codec?: Codec): Promise<ByteBuffer>;
	create<T extends Data>(codec?: Codec): Hasher<T>;
	algorithm: string;
}

/**
 * A signing function.
 */
export interface SignFunction {
	(key: Key, data: ByteBuffer): Promise<ByteBuffer>;
	(key: Key, data: string, codec?: Codec): Promise<ByteBuffer>;
	create<T extends Data>(key: Key, codec?: Codec): Signer<T>;
	algorithm: string;
}

/**
 * The current provider. Providers supply concrete implementations of the API described here. Users should not typically
 * need to access providers directly.
 */
let provider: CryptoProvider;
let providerPromise: Promise<CryptoProvider>;

/**
 * Gets the HashFunction for a particular algorithm. The algorithm is specified as a string for simplicity and
 * extensibility.
 */
export function getHash(algorithm: string): HashFunction {
	// If a provider has been loaded, defer to its getHash
	if (provider) {
		return provider.getHash(algorithm);
	}

	// Before a provider has been loaded, check whether the requested algorithm is one of the standard set. After a
	// provider is loaded, it will handle algorithm verification itself.
	if (!(algorithm in HASH_ALGORITHMS)) {
		throw new Error('invalid algorithm; available algorithms are [ \'' +
			Object.keys(HASH_ALGORITHMS).join('\', \'') + '\' ]');
	}

	let realHash: HashFunction;
	const hashPromise = new Promise<HashFunction>(function (resolve, reject) {
		getProvider().then(function (provider) {
			realHash = provider.getHash(algorithm);
			resolve(realHash);
		}).catch(function (error) {
			reject(error);
		});
	});

	// Return a wrapper that will defer calls to the hash until a provider has been loaded.
	const hashFunction = <HashFunction> function (data: Data, codec?: Codec): Promise<ByteBuffer> {
		if (realHash) {
			return realHash(<any> data, codec);
		}
		return hashPromise.then<ByteBuffer>(function (hash) {
			return hash(<any> data, codec);
		});
	};

	// Return a wrapper class that will defer calls until a provider has been loaded and an actual Hasher instance has
	// been created.
	hashFunction.create = function<T extends Data> (codec?: Codec): Hasher<T> {
		if (realHash) {
			hashFunction.create = realHash.create.bind(realHash);
			return realHash.create(codec);
		}
		return new HasherWrapper(hashPromise, codec);
	};

	return hashFunction;
}

/**
 * Gets the SignFunction for a particular algorithm. The algorithm is specified as a string for simplicity and
 * extensibility.
 */
export function getSign(algorithm: string): SignFunction {
	// If a provider has been loaded, defer to its getSign
	if (provider) {
		return provider.getSign(algorithm);
	}

	// Before a provider has been loaded, check whether the requested algorithm is one of the standard set. After a
	// provider is loaded, it will handle algorithm verification itself.
	if (!(algorithm in SIGN_ALGORITHMS)) {
		throw new Error('invalid algorithm; available algorithms are [ \'' +
			Object.keys(SIGN_ALGORITHMS).join('\', \'') + '\' ]');
	}

	let realSign: SignFunction;
	const signPromise = new Promise<SignFunction>(function (resolve, reject) {
		getProvider().then(function (provider) {
			realSign = provider.getSign(algorithm);
			resolve(realSign);
		}).catch(function (error) {
			reject(error);
		});
	});

	// Return a wrapper that will defer calls to the sign function until a provider has been loaded.
	const signFunction = <SignFunction> function (key: Key, data: Data, codec?: Codec): Promise<ByteBuffer> {
		if (realSign) {
			return realSign(key, <any> data, codec);
		}
		return signPromise.then<ByteBuffer>(function (sign) {
			return sign(key, <any> data, codec);
		});
	};

	// Return a wrapper class that will defer calls until a provider has been loaded and an actual SignFunction instance
	// has been created.
	signFunction.create = function<T extends Data> (key: Key, codec?: Codec): Signer<T> {
		return new SignerWrapper(signPromise, key, codec);
	};

	return signFunction;
}

/**
 * Returns a promise that resolves to the current provider object.
 */
function getProvider(): Promise<CryptoProvider> {
	if (provider) {
		return Promise.resolve(provider);
	}

	if (providerPromise) {
		return providerPromise;
	}

	providerPromise = new Promise(function (resolve, reject) {
		// Load a platform-specific default provider.
		if (typeof define === 'function' && define.amd) {
			function loadProvider(mid: string) {
				require([ mid ], function (_provider: CryptoProvider) {
					// Don't overwrite a provider if one has already been set
					if (!provider) {
						provider = _provider;
					}
					resolve(provider);
				});
			}

			if (has('host-node')) {
				loadProvider('./providers/node');
			}
			else if (has('webcrypto')) {
				loadProvider('./providers/webcrypto');
			}
			else {
				loadProvider('./providers/script');
			}
		}
		else if (has('host-node')) {
			provider = require('./providers/node');
			resolve(provider);
		}
		else {
			reject(new Error('Unknown environment or loader'));
		}
	});

	return providerPromise;
}

/**
 * Sets the implementation provider.
 *
 * The provider may either be a loaded provider or a Promise that will resolve to a provider.
 */
export function setProvider(_provider: CryptoProvider | Promise<CryptoProvider>): void {
	providerPromise = provider = null;

	if (_provider) {
		if ((<any> _provider).then) {
			providerPromise = <Promise<CryptoProvider>> _provider;
		}
		else if ((<any> _provider).getHash) {
			provider = <CryptoProvider> _provider;
		}
	}
}

/**
 * An object for hashing a data stream.
 */
export interface Hasher<T extends Data> extends Sink<T> {
	digest: Promise<ByteBuffer>;  // read only
}

/**
 * Call a method that returns a promise, or return a resolved Promise if the method doesn't exist on the object
 */
function callOrNoop(object: any, methodName: string, ...args: any[]): Promise<any> {
	const method: Function = object[methodName];
	if (!method) {
		return Promise.resolve()
	}
	return method.apply(object, args);
}

function bindOrUndefined(object: any, methodName: string): any {
	const method: Function = object[methodName];
	if (method) {
		return method.bind(object);
	}
}

/**
 * A wrapper around a Promise<HashFunction> that will defer calls while a provider is asynchronously loaded.
 */
class HasherWrapper<T extends Data> implements Hasher<T> {
	constructor(hashPromise: Promise<HashFunction>, codec: Codec) {
		Object.defineProperty(this, '_promise', {
			value: new Promise((resolve, reject) => {
				hashPromise.then(
					(hashFunction) => {
						// When the hash function resolves, create a Hasher and replace this object's methods with
						// pointers to the corresponding methods on the Hasher.
						const hasher = hashFunction.create(codec);
						this.abort = bindOrUndefined(hasher, 'abort');
						this.close = bindOrUndefined(hasher, 'close');
						this.start = bindOrUndefined(hasher, 'start');
						this.write = bindOrUndefined(hasher, 'write');
						resolve(hasher);
					},
					function (error) {
						reject(error);
					}
				);
			})
		});

		Object.defineProperty(this, 'digest', {
			enumerable: true,
			value: new Promise((resolve, reject) => {
				this._promise.then(
					function (hasher) {
						resolve(hasher.digest);
					},
					function (error) {
						reject(error);
					}
				);
			})
		});
	}

	private _promise: Promise<Hasher<T>>;

	digest: Promise<ByteBuffer>;

	// Sink methods; the provider may or may not implement these, so call them with callOrNoop

	abort(reason?: Error): Promise<void> {
		return this._promise.then(function (hasher) {
			return callOrNoop(hasher, 'abort', reason);
		});
	}

	close(): Promise<void> {
		return this._promise.then(function (hasher) {
			return callOrNoop(hasher, 'close');
		});
	}

	start(error: (error: Error) => void): Promise<void> {
		return this._promise.then(function (hasher) {
			return callOrNoop(hasher, 'start', error);
		});
	}

	write(chunk: T): Promise<void> {
		return this._promise.then(function (hasher) {
			return callOrNoop(hasher, 'write', chunk);
		});
	}
}

/**
 * A cryptographic key.
 */
export interface Key {
	algorithm: string,
	data: Data
}

/**
 * An object for signing a data stream.
 */
export interface Signer<T extends Data> extends Sink<T> {
	signature: Promise<ByteBuffer>;  // read only
}

/**
 * A wrapper around a Promise<SignFunction> that will defer calls while a provider is asynchronously loaded.
 */
class SignerWrapper<T extends Data> implements Signer<T> {
	constructor(signPromise: Promise<SignFunction>, key: Key, codec: Codec) {
		Object.defineProperty(this, '_promise', {
			value: new Promise((resolve, reject) => {
				signPromise.then((signFunction) => {
					// When the sign function resolves, create a Signer and replace this object's methods with
					// pointers to the corresponding methods on the Signer.
					const signer = signFunction.create(key, codec);
					this.abort = bindOrUndefined(signer, 'abort');
					this.close = bindOrUndefined(signer, 'close');
					this.start = bindOrUndefined(signer, 'start');
					this.write = bindOrUndefined(signer, 'write');
					resolve(signer);
				}).catch(function (error) {
					reject(error);
				});
			})
		});

		Object.defineProperty(this, 'signature', {
			value: new Promise((resolve, reject) => {
				this._promise.then(
					function (signer) {
						resolve(signer.signature);
					},
					function (error) {
						reject(error);
					}
				);
			})
		});
	}

	private _promise: Promise<Signer<T>>;

	signature: Promise<ByteBuffer>;

	// Sink methods; the provider may or may not implement these, so call them with callOrNoop

	abort(reason?: Error): Promise<void> {
		return this._promise.then(function (signer) {
			return callOrNoop(signer, 'abort', reason);
		});
	}

	close(): Promise<void> {
		return this._promise.then(function (signer) {
			return callOrNoop(signer, 'close');
		});
	}

	start(error: (error: Error) => void): Promise<void> {
		return this._promise.then(function (signer) {
			return callOrNoop(signer, 'start', error);
		});
	}

	write(chunk: T): Promise<void> {
		return this._promise.then(function (signer) {
			return callOrNoop(signer, 'write', chunk);
		});
	}
}
