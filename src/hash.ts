import Promise from 'dojo-core/Promise';
import WritableStream from 'dojo-core/streams/WritableStream';
import { Binary, Codec, Data, provider } from './main';

export { Binary, Codec, Data, provider } from './main';

/**
 * Creates a Hasher for a particular algorithm. The created Hasher performs lookup on the provider whenever it's called.
 * The algorithm is specified as a string for simplicity (and because this is internal).
 */
function createHasher(algorithm: string): Hasher {
	const hasher = <Hasher> function (data: Data, codec?: Codec): Promise<Binary> {
		return provider.hash[algorithm](<any> data, codec);
	}
	hasher.create = function<T extends Data> (codec?: Codec): Hash<T> {
		return provider.hash[algorithm].create<T>(codec);
	}
	return hasher;
}

/**
 * A hashing object
 */
export interface Hash<T extends Data> extends WritableStream<T> {
	// start will generally be a nop for hashes
	start(): Promise<void>;
	write(chunk: T): Promise<void>;
	close(): Promise<void>;
	digest: Promise<Binary>;  // read only
}

/**
 * A hashing function
 */
export interface Hasher {
	(data: Binary): Promise<Binary>;
	(data: string, codec?: Codec): Promise<Binary>;
	create<T extends Data>(codec?: Codec): Hash<T>;
}

/**
 * Something that provides a suite of hash algorithm implementations.
 */
export interface HashProvider {
	md5: Hasher,
	sha1: Hasher,
	sha256: Hasher,
	[ algorithm: string ]: Hasher
}

export const md5 = createHasher('md5');
export const sha1 = createHasher('sha1');
export const sha256 = createHasher('sha256');
