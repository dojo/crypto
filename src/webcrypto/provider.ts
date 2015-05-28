import { CryptoProvider } from '../main';
import { md5, sha1, sha256 } from './hash';
import { hmac } from './hmac';

const provider = <CryptoProvider> {
	hash: {
		md5: md5,
		sha1: sha1,
		sha256: sha256
	},
	hmac: hmac
};

export default provider;
