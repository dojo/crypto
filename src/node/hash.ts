import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, Hasher, HashFunction } from '../hash';
import * as crypto from 'crypto';

/**
 * Returns the name of a Node encoding scheme that corresponds to a particular Codec.
 */
function toEncoding(codec?: Codec) {
	return codec ? String(codec) : undefined;
}

/**
 * Hashes a chunk of data.
 */
function nodeHash(algorithm: string, data: Data, codec?: Codec): Promise<Binary> {
	const hash = crypto.createHash(algorithm);
	const encoding = toEncoding(codec);
	hash.update(data, encoding);
	return Promise.resolve(hash.digest());
}

// Cache a resolved Promise to return from the stream methods.
const resolvedPromise = Promise.resolve();

/**
 * An object that can be used to hash a stream of data.
 */
class NodeHasher<T extends Data> implements Hasher<T> {
	constructor(algorithm: string, encoding: string) {
		Object.defineProperty(this, '_hash', {
			configurable: true,
			value: crypto.createHash(algorithm)
		});
		Object.defineProperty(this, '_encoding', { value: encoding });
		Object.defineProperty(this, 'digest', {
			enumerable: true,
			value: new Promise((resolve, reject) => {
				Object.defineProperty(this, '_resolve', { value: resolve });
				Object.defineProperty(this, '_reject', { value: reject });
			})
		});
	}

	private _hash: crypto.Hash;
	private _encoding: string;
	private _resolve: (value: any) => void;
	private _reject: (reason: Error) => void;

	digest: Promise<Binary>;

	abort(reason?: Error): Promise<void> {
		if (this._hash) {
			// Release the reference to the Hash instance and reject the digest
			Object.defineProperty(this, '_hash', { value: undefined });
			this._reject(reason);
		}
		return resolvedPromise;
	}

	close(): Promise<void> {
		if (this._hash) {
			this._resolve(this._hash.digest());
			// Release the reference to the Hmac/Signer instance and reject the digest
			Object.defineProperty(this, '_hash', { value: undefined });
		}
		return resolvedPromise;
	}

	start(error: (error: Error) => void): Promise<void> {
		// Nothing to do to start a hash
		return resolvedPromise;
	}

	write(chunk: T): Promise<void> {
		if (this._hash) {
			this._hash.update(chunk, this._encoding);
		}
		return resolvedPromise;
	}
}

function createHashFunction(algorithm: string) {
	const hasher = <HashFunction> function (data: Data, codec?: Codec): Promise<Binary> {
		return nodeHash(algorithm, data, codec);
	}
	hasher.create = function<T extends Data> (codec?: Codec): Hasher<T> {
		return new NodeHasher<T>(algorithm, toEncoding(codec));
	}
	hasher.algorithm = algorithm;
	return hasher;
}

export const md5 = createHashFunction('md5');
export const sha1 = createHashFunction('sha1');
export const sha256 = createHashFunction('sha256');
