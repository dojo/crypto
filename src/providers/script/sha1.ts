/*
 * A port of Paul Johnstone's SHA1 implementation
 *
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 *
 * Dojo port by Tom Trenka
 */

import { ByteBuffer } from 'dojo-core/encoding';
import { MathFunction, ScriptHash, addWords, bytesToWords, wordsToBytes } from './base';

const S: MathFunction = function (n, c) {
	return (n << c) | (n >>> (32 - c));
}
const FT: MathFunction = function (t, b, c, d) {
	if (t < 20) {
		return (b & c) | (~b & d);
	}
	if (t < 40) {
		return b ^ c ^ d;
	}
	if (t < 60) {
		return (b & c) | (b & d) | (c & d);
	}
	return b ^ c ^ d;
}
const KT: MathFunction = function (t) {
	return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 : (t < 60) ? -1894007588 : -899497514;
}

const sha1 = <ScriptHash> function (bytes: ByteBuffer): ByteBuffer {
	const numBits = bytes.length * 8;
	const words = bytesToWords(bytes);

	// Pad the input
	words[numBits >> 5] |= 0x80 << (24 - numBits % 32);
	words[((numBits + 64 >> 9) << 4) + 15] = numBits;

	const w = new Array(80);

	// Initialize state
	let a = 0x67452301;
	let b = 0xEFCDAB89;
	let c = 0x98BADCFE;
	let d = 0x10325476;
	let e = 0xC3D2E1F0;

	const numWords = words.length;
	for (let i = 0; i < numWords; i += 16) {
		const olda = a;
		const oldb = b;
		const oldc = c;
		const oldd = d;
		const olde = e;

		for (let t = 0; t < 80; t++) {
			if (t < 16) {
				w[t] = words[i + t];
			}
			else {
				w[t] = S(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
			}

			const temp = addWords(S(a, 5), FT(t, b, c, d), e, w[t], KT(t));
			e = d; 
			d = c;
			c = S(b, 30);
			b = a;
			a = temp;
		}

		a = addWords(a, olda);
		b = addWords(b, oldb);
		c = addWords(c, oldc);
		d = addWords(d, oldd);
		e = addWords(e, olde);
	}

	return wordsToBytes([ a, b, c, d, e ]);
}
sha1.blockSize = 512;

export default sha1;
