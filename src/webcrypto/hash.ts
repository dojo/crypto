import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, Hasher, HashFunction } from '../hash';

export let md5 = <HashFunction> function (data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
md5.create = function<T extends Data> (codec?: Codec): Hasher<T> {
	return null;
}

export let sha1 = <HashFunction> function (data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
sha1.create = function<T extends Data> (codec?: Codec): Hasher<T> {
	return null;
}

export let sha256 = <HashFunction> function (data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
sha256.create = function<T extends Data> (codec?: Codec): Hasher<T> {
	return null;
}
