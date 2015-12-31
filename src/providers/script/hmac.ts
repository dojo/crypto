import { ByteBuffer, utf8 } from 'dojo-core/encoding';
import { Endian, ScriptHash, bytesToWords } from './base';
import { Key } from '../../crypto';

export default function hmac(hash: ScriptHash, data: ByteBuffer, key: ByteBuffer): ByteBuffer {
	// Prepare the key
	if (key.length > 4 * 16 * 32) {
		key = hash(key);
	}

	// Set up the pads
	const numBytes = Math.ceil(hash.blockSize / 32) * 4;
	const ipad = new Array(numBytes);
	const opad = new Array(numBytes);
	for (let i = 0; i < numBytes; i++) {
		ipad[i] = key[i] ^ 0x36;
		opad[i] = key[i] ^ 0x5c;
	}

	// Make the final digest
	const r1 = hash(ipad.concat(data));
	const r2 = hash(opad.concat(r1));

	return r2;
};
