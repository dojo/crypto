import * as crypto from 'crypto';
import Promise from 'dojo-core/Promise';
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
	hmac.update(data, encoding);
	return Promise.resolve(hmac.digest());
}

/**
 * An object that can be used to generate a signature for a stream of data.
 */
class NodeSigner<T extends Data> implements Signer<T> {
	constructor(algorithm: string, key: Key, encoding: string) {
		Object.defineProperty(this, '_sign', {
			configurable: true,
			value: crypto.createHmac(key.algorithm, <Buffer> key.data)
		});
		Object.defineProperty(this, '_encoding', { value: encoding });
		Object.defineProperty(this, 'signature', {
			value: new Promise((resolve, reject) => {
				Object.defineProperty(this, '_resolve', { value: resolve });
				Object.defineProperty(this, '_reject', { value: reject });
			})
		});
	}

	private _sign: crypto.Hmac;
	private _encoding: string;
	private _resolve: (value: any) => void;
	private _reject: (reason: Error) => void;

	signature: Promise<ByteBuffer>;

	abort(reason?: Error): Promise<void> {
		if (this._sign) {
			// Release the reference to the Hmac/Signer instance and reject the signature
			Object.defineProperty(this, '_sign', { value: undefined });
			this._reject(reason);
		}
		return resolvedPromise;
	}

	close(): Promise<void> {
		if (this._sign) {
			const result = (<crypto.Hmac> this._sign).digest();
			// Release the reference to the Hmac/Signer instance
			Object.defineProperty(this, '_sign', { value: undefined });
			this._resolve(result);
		}
		return resolvedPromise;
	}

	start(error: (error: Error) => void): Promise<void> {
		// Nothing to do to start a signer
		return resolvedPromise;
	}

	write(chunk: T): Promise<void> {
		if (this._sign) {
			// The node typing for Sign#update is incorrect -- it shares the same signature as Hash#update
			this._sign.update.call(this._sign, chunk, this._encoding);
		}
		return resolvedPromise;
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
