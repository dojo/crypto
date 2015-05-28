import { CryptoProvider } from '../main';
import { md5, sha1, sha256 } from './hash';
import { hmac } from './sign';

const provider: CryptoProvider = {
	hash: {
		md5,
		sha1,
		sha256
	},
	sign: {
		hmac
	}
};

export default provider;
