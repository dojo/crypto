import { Hasher, HashProvider } from './hash';
import { Signer, SignatureProvider } from './sign';
import Promise from 'dojo-core/Promise';
import has from 'dojo-core/has';
import scriptProvider from './script/provider';
import nodeProvider from './node/provider';
import webProvider from './webcrypto/provider';

export type Binary = Buffer | ArrayBufferView;
export type Data = string | Binary;
// TODO: this should be an encoding Codec (or equivalent) when that exists
export type Codec = string;

/**
 * An interface describing a cryptographic provider.
 */
export interface CryptoProvider {
	hash: HashProvider,
	sign: SignatureProvider
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
