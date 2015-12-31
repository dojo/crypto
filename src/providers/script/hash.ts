import * as crypto from 'crypto';
import Promise, { State } from 'dojo-core/Promise';
import { ByteBuffer, Codec, utf8 } from 'dojo-core/encoding';
import { Data, Hasher, HashFunction } from '../../crypto';
import { sha224, sha256 } from './sha32';
import { sha384, sha512 } from './sha64';
import { ScriptHash } from './base';
import sha1 from './sha1';
import md5 from './md5';

/**
 * A mapping of crypto algorithm names to implementations
 */
export const ALGORITHMS: { [key: string]: ScriptHash } = {
	md5: md5,
	sha1: sha1,
	sha224: sha224,
	sha256: sha256,
	sha384: sha384,
	sha512: sha512
};

/**
 * Hashes a chunk of data.
 */
function hash(algorithm: string, data: Data, codec: Codec): Promise<ByteBuffer> {
	if (typeof data === 'string') {
		data = codec.encode(<string> data);
	}
	return Promise.resolve(ALGORITHMS[algorithm](<ByteBuffer> data));
}

// Cache a resolved Promise to return from the stream methods.
const resolvedPromise = Promise.resolve();

/**
 * An object that can be used to hash a stream of data.
 */
class ScriptHasher<T extends Data> implements Hasher<T> {
	constructor(algorithm: string, codec: Codec) {
		Object.defineProperty(this, '_hash', {
			configurable: true,
			value: ALGORITHMS[algorithm]
		});
		Object.defineProperty(this, '_codec', { value: codec });
		Object.defineProperty(this, '_buffer', {
			writable: true,
			value: []
		});
		Object.defineProperty(this, 'digest', {
			enumerable: true,
			value: new Promise((resolve, reject) => {
				Object.defineProperty(this, '_resolve', { value: resolve });
				Object.defineProperty(this, '_reject', { value: reject });
			})
		});
	}

	private _buffer: number[];
	private _codec: Codec;
	private _hash: (data: ByteBuffer) => ByteBuffer;
	private _reject: (reason: Error) => void;
	private _resolve: (value: any) => void;

	digest: Promise<ByteBuffer>;

	abort(reason?: Error): Promise<any> {
		if (this.digest.state !== State.Pending) {
			return this.digest;
		}

		// Release the reference to the internal buffer and reject the digest
		this._buffer = undefined;
		this._reject(reason);
		return resolvedPromise;
	}

	close(): Promise<any> {
		if (this.digest.state !== State.Pending) {
			return this.digest;
		}

		this._resolve(this._hash(this._buffer));
		// Release the reference to the buffer
		this._buffer = undefined;
		return resolvedPromise;
	}

	write(chunk: T): Promise<any> {
		if (this.digest.state !== State.Pending) {
			return this.digest;
		}

		try {
			if (typeof chunk === 'string') {
				let chunkString: string = <any> chunk;
				this._buffer = this._buffer.concat(this._codec.encode(chunkString));
			}
			else {
				let chunkBuffer: number[] = <any> chunk;
				this._buffer = this._buffer.concat(chunkBuffer);
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
		return hash(algorithm, data, codec);
	};
	hasher.create = function<T extends Data> (codec: Codec = utf8): Hasher<T> {
		return new ScriptHasher<T>(algorithm, codec);
	};
	hasher.algorithm = algorithm;

	return hasher;
}
