import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, Hasher, Hmac, Signer } from '../hmac';

export let hmac = <Signer> function (hasher: Hasher, key: Data, data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
hmac.create = function<T extends Data> (hasher: Hasher, key: Data, codec?: Codec): Hmac<T> {
	return null;
}
