import Promise from 'dojo-core/Promise';
import { Sink } from 'dojo-core/streams/WritableStream';
import { Binary, Codec, Data, provider } from './main';

export { Binary, Codec, Data, provider } from './main';

/**
 * Creates a Hasher for a particular algorithm. The created Hasher performs lookup on the provider whenever it's called.
 * The algorithm is specified as a string for simplicity (and because this is internal).
 */
function createHashFunction(algorithm: string): HashFunction {
	const hashFunction = <HashFunction> function (data: Data, codec?: Codec): Promise<Binary> {
		return provider.hash[algorithm](<any> data, codec);
	}
	Object.defineProperty(hashFunction, 'create', {
		enumerable: true,
		value: function<T extends Data> (codec?: Codec): Hasher<T> {
			return provider.hash[algorithm].create<T>(codec);
		}
	});
	Object.defineProperty(hashFunction, 'algorithm', {
		enumerable: true,
		value: algorithm
	});
	return hashFunction;
}

/**
 * An object that can hash a stream of data.
 */
export interface Hasher<T extends Data> extends Sink<T> {
	digest: Promise<Binary>;  // read only
}

/**
 * A hash function
 */
export interface HashFunction {
	(data: Binary): Promise<Binary>;
	(data: string, codec?: Codec): Promise<Binary>;
	create<T extends Data>(codec?: Codec): Hasher<T>;
	algorithm: string;
}

/**
 * Something that provides a suite of hash algorithm implementations.
 */
export interface HashProvider {
	md5: HashFunction,
	sha1: HashFunction,
	sha256: HashFunction,
	[ algorithm: string ]: HashFunction
}

export const md5 = createHashFunction('md5');
export const sha1 = createHashFunction('sha1');
export const sha256 = createHashFunction('sha256');
