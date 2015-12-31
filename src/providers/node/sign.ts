import * as crypto from 'crypto';
import Promise, { State } from 'dojo-core/Promise';
import { ByteBuffer, Codec, utf8 } from 'dojo-core/encoding';
import { Data, Key, Signer, SignFunction } from '../../crypto';
import { getEncodingName } from './util';

/**
 * A mapping of crypto algorithm names to their node equivalents
 */
const ALGORITHMS = {
	hmac: 'hmac'
};

const resolvedPromise = Promise.resolve();

/**
 * Generates a signature for a chunk of data.
 */
function sign(algorithm: string, key: Key, data: Data, codec: Codec): Promise<ByteBuffer> {
	const hashAlgorithm = key.algorithm;
	const hmac = crypto.createHmac(hashAlgorithm, <Buffer> key.data);
	const encoding = getEncodingName(codec);

	// Node crypto requires the input data to be a string or Buffer, so convert arrays to Buffers
	if (Array.isArray(data)) {
		data = new Buffer(<number[]> data);
	}

	hmac.update(data, encoding);
	return Promise.resolve(hmac.digest());
}

/**
 * An object that can be used to generate a signature for a stream of data.
 */
class NodeSigner<T extends Data> implements Signer<T> {
	constructor(algorithm: string, key: Key, encoding: string) {
		Object.defineProperty(this, 'signature', {
			value: new Promise((resolve, reject) => {
				Object.defineProperty(this, '_resolve', { value: resolve });
				Object.defineProperty(this, '_reject', { value: reject });
			})
		});

		try {
			// Throw a useful error if the key is invalid
			if (typeof key.data !== 'string' && !(key.data instanceof Buffer)) { 
				throw new Error('Key data must be a non-null string or buffer');
			}

			Object.defineProperty(this, '_sign', {
				configurable: true,
				value: crypto.createHmac(key.algorithm, <Buffer> key.data)
			});
			Object.defineProperty(this, '_encoding', { value: encoding });
		}
		catch (error) {
			this._reject(error);
		}
	}

	private _sign: crypto.Hmac;
	private _encoding: string;
	private _resolve: (value: any) => void;
	private _reject: (reason: Error) => void;

	signature: Promise<ByteBuffer>;

	abort(reason?: Error): Promise<any> {
		if (this.signature.state !== State.Pending) {
			return this.signature;
		}

		// Release the reference to the Hmac/Signer instance and reject the signature
		Object.defineProperty(this, '_sign', { value: undefined });
		this._reject(reason);
		return resolvedPromise;
	}

	close(): Promise<any> {
		if (this.signature.state !== State.Pending) {
			return this.signature;
		}

		const result = (<crypto.Hmac> this._sign).digest();
		// Release the reference to the Hmac/Signer instance
		Object.defineProperty(this, '_sign', { value: undefined });
		this._resolve(result);
		return resolvedPromise;
	}

	write(chunk: T): Promise<any> {
		if (this.signature.state !== State.Pending) {
			return this.signature;
		}

		let _chunk: T | Buffer = chunk;
		// Node can't work with Arrays, so convert them to Buffers
		// The node typing for Sign#update is incorrect -- it shares the same signature as Hash#update
		try {
			if (Array.isArray(chunk)) {
				this._sign.update.call(this._sign, new Buffer(<any> chunk, this._encoding));
			}
			else {
				this._sign.update.call(this._sign, chunk, this._encoding);
			}
			return resolvedPromise;
		}
		catch (error) {
			this._reject(error);
			return this.signature;
		}
	}
}

export default function getSign(algorithm: string): SignFunction {
	if (!(algorithm in ALGORITHMS)) {
		throw new Error('invalid algorithm; available algorithms are [ \'' + Object.keys(ALGORITHMS).join('\', \'') + '\' ]');
	}

	const signFunction = <SignFunction> function (key: Key, data: Data, codec: Codec = utf8): Promise<ByteBuffer> {
		return sign(algorithm, key, data, codec);
	};
	signFunction.create = function<T extends Data> (key: Key, codec: Codec = utf8): Signer<T> {
		return new NodeSigner<T>(algorithm, key, getEncodingName(codec));
	};

	return signFunction;
}
