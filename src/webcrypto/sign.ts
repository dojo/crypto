import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, Hasher, Key, Signature, Signer } from '../sign';

export let hmac = <Signer> function (key: Key, data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
hmac.create = function<T extends Data> (key: Key, codec?: Codec): Signature<T> {
	return null;
}
