import WritableStream from 'dojo-core/streams/WritableStream';
import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, provider } from './main';
import { Hasher, Hash } from './hash';

export { Binary, Codec, Data, provider } from './main';
export { Hasher } from './hash';

/**
 * Creates a Signer for a particular algorithm. The created Signer performs lookup on the provider whenever it's called.
 * The algorithm is specified as a string for simplicity (and because this is internal).
 */
function createSigner(algorithm: string): Signer {
	const signer = <Signer> function (key: Key, data: Data, codec?: Codec): Promise<Binary> {
		return provider.sign[algorithm](key, <any> data, codec);
	}
	signer.create = function<T extends Data> (key: Key, codec?: Codec): Hash<T> {
		return provider.sign[algorithm].create<T>(key, codec);
	}
	return signer;
}

/**
 * A signing key.
 */
export interface Key {
	hasher: Hasher,
	data: Data
}

/**
 * An digital signing object
 */
export interface Signature<T extends Data> extends WritableStream<T> {
	// start will generally be a nop for hashes
	start(): Promise<void>;
	write(chunk: T): Promise<void>;
	close(): Promise<void>;
	digest: Promise<Binary>;  // read only
}

/**
 * An digital signing function
 */
export interface Signer {
	(key: Key, data: Binary): Promise<Binary>;
	(key: Key, data: string, codec?: Codec): Promise<Binary>;
	create<T extends Data>(key: Key, codec?: Codec): Signature<T>;
}

/**
 * Something that provides a suite of hash algorithm implementations.
 */
export interface SignatureProvider {
	hmac: Signer,
	[ algorithm: string ]: Signer
}

export const hmac = createSigner('hmac');
