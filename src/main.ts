import { Hasher, HashProvider } from './hash';
import { Signer, SigningProvider } from './sign';
import Promise from 'dojo-core/Promise';
import has, { add as hasAdd } from 'dojo-core/has';
import global from 'dojo-core/global';
import scriptProvider from './script/provider';
import nodeProvider from './node/provider';
import webProvider from './webcrypto/provider';

hasAdd('webcrypto', typeof global.SubtleCrypto !== 'undefined');

export type Binary = ArrayBufferView | Buffer | number[];
// TODO: this should be an encoding Codec (or equivalent) when that exists
export type Codec = string;
export type Data = string | Binary;

/**
 * An interface describing a cryptographic provider.
 */
export interface CryptoProvider {
	hash: HashProvider,
	sign: SigningProvider
}

/**
 * The current provider.
 */
export let provider: CryptoProvider;

if (has('host-node')) {
	provider = nodeProvider;
}
else if (has('webcrypto')) {
	provider = webProvider;
}
else {
	provider = scriptProvider;
}

export function main() {
	return {};
}
