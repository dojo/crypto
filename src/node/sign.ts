import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, Hasher, Key, Signer, SigningFunction } from '../sign';
import * as hash from '../hash';
import * as crypto from 'crypto';

/**
 * Returns the name of a Node encoding scheme that corresponds to a particular Codec.
 */
function toEncoding(codec?: Codec) {
	return codec ? String(codec) : undefined;
}

/**
 * Get the name corresponding to a key's algorithm property.
 */
function getAlgorithmName(key: Key): string {
	return key.algorithm.algorithm;
}

/**
 * Generates a signature for a chunk of data.
 */
function nodeSign(algorithm: string, key: Key, data: Data, codec?: Codec): Promise<Binary> {
	const hashAlgorithm = getAlgorithmName(key);
	if (algorithm === 'hmac') {
		let keyData = key.data;
		const hmac = crypto.createHmac(hashAlgorithm, <Buffer> key.data);
		const encoding = toEncoding(codec);
		hmac.update(data, encoding);
		return Promise.resolve(hmac.digest());
	}
	else {
		// TODO: work with Node's crypto.createSign
	}
}

// Cache a resolved Promise to return from the stream methods.
const resolvedPromise = Promise.resolve();

/**
 * An object that can be used to generate a signature for a stream of data.
 */
class NodeSigner<T extends Data> implements Signer<T> {
	constructor(algorithm: string, key: Key, encoding: string) {
		if (algorithm === 'hmac') {
			Object.defineProperty(this, '_sign', {
				configurable: true,
				value: crypto.createHmac(key.algorithm.algorithm, <Buffer> key.data)
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

function createSigningFunction(algorithm: string) {
	const signingFunction = <SigningFunction> function (key: Key, data: Data, codec?: Codec): Promise<Binary> {
		return nodeSign(algorithm, key, data, codec);
	}
	signingFunction.create = function<T extends Data> (key: Key, codec?: Codec): Signer<T> {
		return new NodeSigner<T>(algorithm, key, toEncoding(codec));
	}
	return signingFunction;
}

export const hmac = createSigningFunction('hmac');
