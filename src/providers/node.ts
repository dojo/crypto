import createHash, { ALGORITHMS } from './node/hash';
import createSign from './node/sign';
import { CryptoProvider, Key } from '../crypto';

const nodeProvider: CryptoProvider = {
	createHash: createHash,
	createSign: createSign
};

export default nodeProvider;
