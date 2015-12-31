import * as crypto from 'crypto';
import Promise, { State } from 'dojo-core/Promise';
import { ByteBuffer, Codec, utf8 } from 'dojo-core/encoding';
import { Data, Hasher, HashFunction } from '../../crypto';
import { getEncodingName } from './util';

/**
 * A mapping of crypto algorithm names to their node equivalents
 */
const ALGORITHMS = {
	md5: 'md5',
	sha1: 'sha1',
	sha256: 'sha256'
};

/**
 * Hashes a chunk of data.
 */
function nodeHash(algorithm: string, data: Data, codec: Codec): Promise<ByteBuffer> {
	const hash = crypto.createHash(algorithm);
	const encoding = getEncodingName(codec);
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

	digest: Promise<ByteBuffer>;

	abort(reason?: Error): Promise<any> {
		if (this.digest.state !== State.Pending) {
			return this.digest;
		}

		// Release the reference to the Hash instance and reject the digest
		Object.defineProperty(this, '_hash', { value: undefined });
		this._reject(reason);
		return resolvedPromise;
	}

	close(): Promise<any> {
		if (this.digest.state !== State.Pending) {
			return this.digest;
		}

		this._resolve(this._hash.digest());
		// Release the reference to the Hash instance
		Object.defineProperty(this, '_hash', { value: undefined });
		return resolvedPromise;
	}

	write(chunk: T): Promise<any> {
		if (this.digest.state !== State.Pending) {
			return this.digest;
		}

		let _chunk: T | Buffer = chunk;
		// Node can't work with Arrays, so convert them to Buffers
		// The node typing for Sign#update is incorrect -- it shares the same signature as Hash#update
		try {
			if (Array.isArray(chunk)) {
				this._hash.update(new Buffer(<any> chunk, this._encoding));
			}
			else {
				this._hash.update(chunk, this._encoding);
			}
			return resolvedPromise;
		}
		catch (error) {
			this._reject(error);
			return this.digest;
		}
	}
}

export default function getHash(algorithm: string): HashFunction {
	const hasher = <HashFunction> function (data: Data, codec: Codec = utf8): Promise<ByteBuffer> {
		return nodeHash(algorithm, data, codec);
	};
	hasher.create = function<T extends Data> (codec: Codec = utf8): Hasher<T> {
		return new NodeHasher<T>(algorithm, getEncodingName(codec));
	};
	hasher.algorithm = algorithm;

	return hasher;
}
