import WritableStream from 'dojo-core/streams/WritableStream';
import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, provider } from './main';
import { Hasher, Hash } from './hash';

export { Binary, Codec, Data, provider } from './main';
export { Hasher } from './hash';

type Key = any;

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
	(key: Data, data: Binary): Promise<Binary>;
	(key: Data, data: string, codec?: Codec): Promise<Binary>;
	create<T extends Data>(hasher: Hasher, key: Data, codec?: Codec): Hmac<T>;
}

/**
 * Computes the HMAC of a chunk of data.
 */
export const hmac = <Signer> function (key: Key, data: Data, codec?: Codec): Promise<Binary> {
	return provider.hmac(key.hasher, <any> data, codec);
}

/**
 * Creates an object that can be used to compute the HMAC of a data stream.
 */
hmac.create = function<T extends Data> (key: Key, codec?: Codec): Hmac<T> {
	return provider.hmac.create<T>(key.hasher, codec);
}
