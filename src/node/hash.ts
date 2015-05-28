import Promise from 'dojo-core/Promise';
import { Binary, Codec, Data, Hash, Hasher } from '../hash';

export let md5 = <Hasher> function (data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
md5.create = function<T extends Data> (codec?: Codec): Hash<T> {
	return null;
}

export let sha1 = <Hasher> function (data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
sha1.create = function<T extends Data> (codec?: Codec): Hash<T> {
	return null;
}

export let sha256 = <Hasher> function (data: Data, codec?: Codec): Promise<Binary> {
	return null;
}
sha256.create = function<T extends Data> (codec?: Codec): Hash<T> {
	return null;
}
