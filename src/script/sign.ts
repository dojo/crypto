import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, Hasher, Key, Signer, SigningFunction } from '../sign';

export let hmac = <SigningFunction> function (key: Key, data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
hmac.create = function<T extends Data> (key: Key, codec?: Codec): Signer<T> {
	return null;
}
