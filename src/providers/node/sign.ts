import * as crypto from 'crypto';
import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, Key, Signer, SignFunction } from '../../crypto';

/**
 * Sign algorithms available through this provider. This object maps crypto API algorithm names to native (Node.js)
 * names.
 */
const ALGORITHMS = {
	hmac: 'hmac',
};

const resolvedPromise = Promise.resolve();

/**
 * Returns the name of a Node encoding scheme that corresponds to a particular Codec.
 */
function getEncodingName(codec?: Codec) {
	return codec ? String(codec) : undefined;
}

/**
 * Generates a signature for a chunk of data.
 */
function sign(algorithm: string, key: Key, data: Data, codec?: Codec): Promise<Binary> {
	const hashAlgorithm = key.algorithm;
	if (algorithm === 'hmac') {
		let keyData = key.data;
		const hmac = crypto.createHmac(hashAlgorithm, <Buffer> key.data);
		const encoding = getEncodingName(codec);
		hmac.update(data, encoding);
		return Promise.resolve(hmac.digest());
	}
	else {
		// TODO: work with Node's crypto.createSign
	}
}

/**
 * An object that can be used to generate a signature for a stream of data.
 */
class NodeSigner<T extends Data> implements Signer<T> {
	constructor(algorithm: string, key: Key, encoding: string) {
		if (algorithm === 'hmac') {
			Object.defineProperty(this, '_sign', {
				configurable: true,
				value: crypto.createHmac(key.algorithm, <Buffer> key.data)
			});
		}
		Object.defineProperty(this, '_encoding', { value: encoding });
		Object.defineProperty(this, 'signature', {
			value: new Promise((resolve, reject) => {
				Object.defineProperty(this, '_resolve', { value: resolve });
				Object.defineProperty(this, '_reject', { value: reject });
			})
		});
	}

	private _sign: crypto.Hmac | crypto.Signer;
	private _encoding: string;
	private _resolve: (value: any) => void;
	private _reject: (reason: Error) => void;

	signature: Promise<Binary>;

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
			let result: Buffer;
			if ('digest' in this._sign) {
				result = (<crypto.Hmac> this._sign).digest();
			}
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
			this._sign.update(chunk);
		}
		return resolvedPromise;
	}
}

export default function createSign(algorithm: string): SignFunction {
	if (!(algorithm in ALGORITHMS)) {
		throw new Error('invalid algorithm');
	}

	const signFunction = <SignFunction> function (key: Key, data: Data, codec?: Codec): Promise<Binary> {
		return sign(algorithm, key, data, codec);
	}
	signFunction.create = function<T extends Data> (key: Key, codec?: Codec): Signer<T> {
		return new NodeSigner<T>(algorithm, key, getEncodingName(codec));
	}

	return signFunction;
}
