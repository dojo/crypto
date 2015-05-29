import { Sink } from 'dojo-core/streams/WritableStream';
import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, provider } from './main';
import { Hasher, HashFunction } from './hash';

export { Binary, Codec, Data, provider } from './main';
export { Hasher } from './hash';

/**
 * Creates a Signer for a particular algorithm. The created Signer performs lookup on the provider whenever it's called.
 * The algorithm is specified as a string for simplicity (and because this is internal).
 */
function createSigningFunction(algorithm: string): SigningFunction {
	const sign = <SigningFunction> function (key: Key, data: Data, codec?: Codec): Promise<Binary> {
		return provider.sign[algorithm](key, <any> data, codec);
	}
	Object.defineProperty(sign, 'create', {
		enumerable: true,
		value: function<T extends Data> (key: Key, codec?: Codec): Signer<T> {
			return provider.sign[algorithm].create<T>(key, codec);
		}
	});
	Object.defineProperty(sign, 'algorithm', {
		enumerable: true,
		value: algorithm
	});
	return sign;
}

/**
 * A signing key.
 */
export interface Key {
	algorithm: HashFunction,
	data: Data
}

/**
 * An digital signing object
 */
export interface Signer<T extends Data> extends Sink<T> {
	signature: Promise<Binary>;  // read only
}

/**
 * An digital signing function
 */
export interface SigningFunction {
	(key: Key, data: Binary): Promise<Binary>;
	(key: Key, data: string, codec?: Codec): Promise<Binary>;
	create<T extends Data>(key: Key, codec?: Codec): Signer<T>;
	algorithm: string;
}

/**
 * Something that provides a suite of signing functions.
 */
export interface SigningProvider {
	hmac: SigningFunction,
	[ algorithm: string ]: SigningFunction
}

export const hmac = createSigningFunction('hmac');
