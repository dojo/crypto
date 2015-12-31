/**
 * A port of Paul Johnstone's MD5 implementation
 * http://pajhome.org.uk/crypt/md5/index.html
 *
 * Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 *
 * Original Dojo port by Tom Trenka
 */

import { Endian, MathFunction, ScriptHash, addWords, bytesToWords, wordsToBytes } from './base';
import { ByteBuffer } from 'dojo-core/encoding';

//	MD5 rounds functions
const R: MathFunction = function (n, c) {
	return (n << c) | (n >>> (32 - c ));
}
const C: MathFunction = function (q, a, b, x, s, t) {
	return addWords(R(addWords(a, q, x, t), s), b);
}
const FF: MathFunction = function (a, b, c, d, x, s, t) {
	return C((b & c) | (~b & d), a, b, x, s, t);
}
const GG: MathFunction = function (a, b, c, d, x, s, t) {
	return C((b & d) | (c & ~d), a, b, x, s, t);
}
const HH: MathFunction = function (a, b, c, d, x, s, t) {
	return C(b ^ c ^ d, a, b, x, s, t);
}
const II: MathFunction = function (a, b, c, d, x, s, t) {
	return C(c ^ (b | ~d), a, b, x, s, t);
}

// Transform constants
const S11 =  7;
const S12 = 12;
const S13 = 17;
const S14 = 22;
const S21 =  5;
const S22 =  9;
const S23 = 14;
const S24 = 20;
const S31 =  4;
const S32 = 11;
const S33 = 16;
const S34 = 23;
const S41 =  6;
const S42 = 10;
const S43 = 15;
const S44 = 21;

/**
 * The core MD5 function
 */
const md5 = <ScriptHash> function (bytes: ByteBuffer): ByteBuffer {
	const numBits = bytes.length * 8;
	const words = bytesToWords(bytes, Endian.Little);

	// Pad input
    words[numBits >> 5] |= 0x80 << (numBits % 32);
    words[(((numBits + 64) >>> 9) << 4) + 14] = numBits;

	// Initialize state
    let a = 0x67452301;
    let b = 0xEFCDAB89;
    let c = 0x98BADCFE;
    let d = 0x10325476;

	const numWords = words.length;
    for (let i = 0; i < numWords; i += 16) {
		const olda = a;
		const oldb = b;
		const oldc = c;
		const oldd = d;

		a = FF(a, b, c, d, words[i +  0], S11, 0xD76AA478);
		d = FF(d, a, b, c, words[i +  1], S12, 0xE8C7B756);
		c = FF(c, d, a, b, words[i +  2], S13, 0x242070DB);
		b = FF(b, c, d, a, words[i +  3], S14, 0xC1BDCEEE);
		a = FF(a, b, c, d, words[i +  4], S11, 0xF57C0FAF);
		d = FF(d, a, b, c, words[i +  5], S12, 0x4787C62A);
		c = FF(c, d, a, b, words[i +  6], S13, 0xA8304613);
		b = FF(b, c, d, a, words[i +  7], S14, 0xFD469501);
		a = FF(a, b, c, d, words[i +  8], S11, 0x698098D8);
		d = FF(d, a, b, c, words[i +  9], S12, 0x8B44F7AF);
		c = FF(c, d, a, b, words[i + 10], S13, 0xFFFF5BB1);
		b = FF(b, c, d, a, words[i + 11], S14, 0x895CD7BE);
		a = FF(a, b, c, d, words[i + 12], S11, 0x6B901122);
		d = FF(d, a, b, c, words[i + 13], S12, 0xFD987193);
		c = FF(c, d, a, b, words[i + 14], S13, 0xA679438E);
		b = FF(b, c, d, a, words[i + 15], S14, 0x49B40821);

		a = GG(a, b, c, d, words[i +  1], S21, 0xF61E2562);
		d = GG(d, a, b, c, words[i +  6], S22, 0xC040B340);
		c = GG(c, d, a, b, words[i + 11], S23, 0x265E5A51);
		b = GG(b, c, d, a, words[i +  0], S24, 0xE9B6C7AA);
		a = GG(a, b, c, d, words[i +  5], S21, 0xD62F105D);
		d = GG(d, a, b, c, words[i + 10], S22, 0x02441453);
		c = GG(c, d, a, b, words[i + 15], S23, 0xD8A1E681);
		b = GG(b, c, d, a, words[i +  4], S24, 0xE7D3FBC8);
		a = GG(a, b, c, d, words[i +  9], S21, 0x21E1CDE6);
		d = GG(d, a, b, c, words[i + 14], S22, 0xC33707D6);
		c = GG(c, d, a, b, words[i +  3], S23, 0xF4D50D87);
		b = GG(b, c, d, a, words[i +  8], S24, 0x455A14ED);
		a = GG(a, b, c, d, words[i + 13], S21, 0xA9E3E905);
		d = GG(d, a, b, c, words[i +  2], S22, 0xFCEFA3F8);
		c = GG(c, d, a, b, words[i +  7], S23, 0x676F02D9);
		b = GG(b, c, d, a, words[i + 12], S24, 0x8D2A4C8A);

		a = HH(a, b, c, d, words[i +  5], S31, 0xFFFA3942);
		d = HH(d, a, b, c, words[i +  8], S32, 0x8771F681);
		c = HH(c, d, a, b, words[i + 11], S33, 0x6D9D6122);
		b = HH(b, c, d, a, words[i + 14], S34, 0xFDE5380C);
		a = HH(a, b, c, d, words[i +  1], S31, 0xA4BEEA44);
		d = HH(d, a, b, c, words[i +  4], S32, 0x4BDECFA9);
		c = HH(c, d, a, b, words[i +  7], S33, 0xF6BB4B60);
		b = HH(b, c, d, a, words[i + 10], S34, 0xBEBFBC70);
		a = HH(a, b, c, d, words[i + 13], S31, 0x289B7EC6);
		d = HH(d, a, b, c, words[i +  0], S32, 0xEAA127FA);
		c = HH(c, d, a, b, words[i +  3], S33, 0xD4EF3085);
		b = HH(b, c, d, a, words[i +  6], S34, 0x04881D05);
		a = HH(a, b, c, d, words[i +  9], S31, 0xD9D4D039);
		d = HH(d, a, b, c, words[i + 12], S32, 0xE6DB99E5);
		c = HH(c, d, a, b, words[i + 15], S33, 0x1FA27CF8);
		b = HH(b, c, d, a, words[i +  2], S34, 0xC4AC5665);

		a = II(a, b, c, d, words[i +  0], S41, 0xF4292244);
		d = II(d, a, b, c, words[i +  7], S42, 0x432AFF97);
		c = II(c, d, a, b, words[i + 14], S43, 0xAB9423A7);
		b = II(b, c, d, a, words[i +  5], S44, 0xFC93A039);
		a = II(a, b, c, d, words[i + 12], S41, 0x655B59C3);
		d = II(d, a, b, c, words[i +  3], S42, 0x8F0CCC92);
		c = II(c, d, a, b, words[i + 10], S43, 0xFFEFF47D);
		b = II(b, c, d, a, words[i +  1], S44, 0x85845DD1);
		a = II(a, b, c, d, words[i +  8], S41, 0x6FA87E4F);
		d = II(d, a, b, c, words[i + 15], S42, 0xFE2CE6E0);
		c = II(c, d, a, b, words[i +  6], S43, 0xA3014314);
		b = II(b, c, d, a, words[i + 13], S44, 0x4E0811A1);
		a = II(a, b, c, d, words[i +  4], S41, 0xF7537E82);
		d = II(d, a, b, c, words[i + 11], S42, 0xBD3AF235);
		c = II(c, d, a, b, words[i +  2], S43, 0x2AD7D2BB);
		b = II(b, c, d, a, words[i +  9], S44, 0xEB86D391);

		a = addWords(a, olda);
		b = addWords(b, oldb);
		c = addWords(c, oldc);
		d = addWords(d, oldd);
	}

	return wordsToBytes([ a, b, c, d ], Endian.Little);
}
md5.blockSize = 512;

export default md5;
