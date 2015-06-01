import Promise from 'dojo-core/Promise';
import global from 'dojo-core/global';
import has, { add as hasAdd } from 'dojo-core/has';
import { Sink } from 'dojo-core/streams/WritableStream';
import nodeProvider from './providers/node';
// import scriptProvider from './providers/script';
// import webProvider from './providers/webcrypto';

hasAdd('webcrypto', typeof global.SubtleCrypto !== 'undefined');

export type Binary = ArrayBufferView | Buffer | number[];
// TODO: this should be an encoding Codec (or equivalent) when that exists
export type Codec = string;
export type Data = string | Binary;

/**
 * An interface describing a cryptographic provider.
 */
export interface CryptoProvider {
	createHash(algorithm: string): HashFunction;
	createSign(algorithm: string): SignFunction;
}

/**
 * The current provider. Providers provide concrete implementations of the API described here. Users will not generally
 * access providers directly.
 */
export let provider: CryptoProvider;

if (has('host-node')) {
	provider = nodeProvider;
}
// else if (has('webcrypto')) {
// 	provider = webProvider;
// }
// else {
// 	provider = scriptProvider;
// }

/**
 * Creates a HashFunction for a particular algorithm. The created Hasher performs lookup on the provider whenever it's
 * called. The algorithm is specified as a string for simplicity (and because this is internal).
 */
export function createHash(algorithm: string): HashFunction {
	return provider.createHash(algorithm);
}

/**
 * Creates a SignFunction for a particular algorithm. The created Signer performs lookup on the provider whenever it's
 * called. The algorithm is specified as a string for simplicity (and because this is internal).
 */
export function createSign(algorithm: string): SignFunction {
	return provider.createSign(algorithm);
}

/**
 * An object that can hash a stream of data.
 */
export interface Hasher<T extends Data> extends Sink<T> {
	digest: Promise<Binary>;  // read only
}

/**
 * A function that can hash a chunk of data.
 */
export interface HashFunction {
	(data: Binary): Promise<Binary>;
	(data: string, codec?: Codec): Promise<Binary>;
	create<T extends Data>(codec?: Codec): Hasher<T>;
	algorithm: string;
}

/**
 * A cryptographic key.
 */
export interface Key {
	algorithm: string,
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
export interface SignFunction {
	(key: Key, data: Binary): Promise<Binary>;
	(key: Key, data: string, codec?: Codec): Promise<Binary>;
	create<T extends Data>(key: Key, codec?: Codec): Signer<T>;
	algorithm: string;
}
