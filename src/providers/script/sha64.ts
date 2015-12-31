import { ByteBuffer, utf8 } from 'dojo-core/encoding';
import Promise from 'dojo-core/Promise';
import { ScriptHash, bytesToWords, wordsToBytes } from './base';
import { Data } from '../../crypto';

/**
 * A 64-bit integer as [ low byte, high byte ]
 */
type Int64 = number[];

/**
 * Create a 64-bit integer from two 32-bit values
 */
function int64(high: number, low: number): Int64 {
	return [ low, high ];
}

/**
 * Copies a value.
 */
function copy(dst: Int64, src: Int64): void {
	dst[0] = src[0];
	dst[1] = src[1];
}

/**
 * Right-rotates a value.
 */
function rotateRight(dst: Int64, src: Int64, shift: number) {
	dst[0] = (src[0] >>> shift) | (src[1] << (32 - shift));
	dst[1] = (src[1] >>> shift) | (src[0] << (32 - shift));
}

/**
 * Reverses the dwords of the source and then rotates right by shift.
 */
function reverseRotateRight(dst: Int64, src: Int64, shift: number) {
	dst[0] = (src[1] >>> shift) | (src[0] << (32 - shift));
	dst[1] = (src[0] >>> shift) | (src[1] << (32 - shift));
}

/**
 * Bitwise-shifts right a 64-bit number by shift.
 */
function shiftRight(dst: Int64, src: Int64, shift: number) {
	dst[0] = (src[0] >>> shift) | (src[1] << (32 - shift));
	dst[1] = (src[1] >>> shift);
}

/**
 * Adds two 64-bit numbers
 */
function add(dst: Int64, x: Int64, y: Int64) {
	const w0 = (x[0] & 0xFFFF) + (y[0] & 0xFFFF);
	const w1 = (x[0] >>> 16) + (y[0] >>> 16) + (w0 >>> 16);
	const w2 = (x[1] & 0xFFFF) + (y[1] & 0xFFFF) + (w1 >>> 16);
	const w3 = (x[1] >>> 16) + (y[1] >>> 16) + (w2 >>> 16);
	dst[0] = (w0 & 0xFFFF) | (w1 << 16);
	dst[1] = (w2 & 0xFFFF) | (w3 << 16);
}

/**
 * Adds four 64-bit numbers
 */
function add4(dst: Int64, a: Int64, b: Int64, c: Int64, d: Int64){
	const w0 = (a[0] & 0xFFFF) + (b[0] & 0xFFFF) + (c[0] & 0xFFFF) + (d[0] & 0xFFFF);
	const w1 = (a[0] >>> 16) + (b[0] >>> 16) + (c[0] >>> 16) + (d[0] >>> 16) + (w0 >>> 16);
	const w2 = (a[1] & 0xFFFF) + (b[1] & 0xFFFF) + (c[1] & 0xFFFF) + (d[1] & 0xFFFF) + (w1 >>> 16);
	const w3 = (a[1] >>> 16) + (b[1] >>> 16) + (c[1] >>> 16) + (d[1] >>> 16) + (w2 >>> 16);
	dst[0] = (w0 & 0xFFFF) | (w1 << 16);
	dst[1] = (w2 & 0xFFFF) | (w3 << 16);
}

/**
 * Adds five 64-bit numbers
 */
function add5(dst: Int64, a: Int64, b: Int64, c: Int64, d: Int64, e: Int64) {
	const w0 = (a[0] & 0xFFFF) + (b[0] & 0xFFFF) + (c[0] & 0xFFFF) + (d[0] & 0xFFFF) + (e[0] & 0xFFFF);
	const w1 = (a[0] >>> 16) + (b[0] >>> 16) + (c[0] >>> 16) + (d[0] >>> 16) + (e[0] >>> 16) + (w0 >>> 16);
	const w2 = (a[1] & 0xFFFF) + (b[1] & 0xFFFF) + (c[1] & 0xFFFF) + (d[1] & 0xFFFF) + (e[1] & 0xFFFF) + (w1 >>> 16);
	const w3 = (a[1] >>> 16) + (b[1] >>> 16) + (c[1] >>> 16) + (d[1] >>> 16) + (e[1] >>> 16) + (w2 >>> 16);
	dst[0] = (w0 & 0xFFFF) | (w1 << 16);
	dst[1] = (w2 & 0xFFFF) | (w3 << 16);
}

// constant K array
const K = [
	int64(0x428A2F98, 0xD728AE22), int64(0x71374491, 0x23EF65CD),
	int64(0xB5C0FBCF, 0xEC4D3B2F), int64(0xE9B5DBA5, 0x8189DBBC), 
	int64(0x3956C25B, 0xF348B538), int64(0x59F111F1, 0xB605D019),
	int64(0x923F82A4, 0xAF194F9B), int64(0xAB1C5ED5, 0xDA6D8118), 
	int64(0xD807AA98, 0xA3030242), int64(0x12835B01, 0x45706FBE),
	int64(0x243185BE, 0x4EE4B28C), int64(0x550C7DC3, 0xD5FFB4E2), 
	int64(0x72BE5D74, 0xF27B896F), int64(0x80DEB1FE, 0x3B1696B1),
	int64(0x9BDC06A7, 0x25C71235), int64(0xC19BF174, 0xCF692694), 
	int64(0xE49B69C1, 0x9EF14AD2), int64(0xEFBE4786, 0x384F25E3),
	int64(0x0FC19DC6, 0x8B8CD5B5), int64(0x240CA1CC, 0x77AC9C65), 
	int64(0x2DE92C6F, 0x592B0275), int64(0x4A7484AA, 0x6EA6E483),
	int64(0x5CB0A9DC, 0xBD41FBD4), int64(0x76F988DA, 0x831153B5), 
	int64(0x983E5152, 0xEE66DFAB), int64(0xA831C66D, 0x2DB43210),
	int64(0xB00327C8, 0x98FB213F), int64(0xBF597FC7, 0xBEEF0EE4), 
	int64(0xC6E00BF3, 0x3DA88FC2), int64(0xD5A79147, 0x930AA725),
	int64(0x06CA6351, 0xE003826F), int64(0x14292967, 0x0A0E6E70), 
	int64(0x27B70A85, 0x46D22FFC), int64(0x2E1B2138, 0x5C26C926),
	int64(0x4D2C6DFC, 0x5AC42AED), int64(0x53380D13, 0x9D95B3DF), 
	int64(0x650A7354, 0x8BAF63DE), int64(0x766A0ABB, 0x3C77B2A8),
	int64(0x81C2C92E, 0x47EDAEE6), int64(0x92722C85, 0x1482353B), 
	int64(0xA2BFE8A1, 0x4CF10364), int64(0xA81A664B, 0xBC423001),
	int64(0xC24B8B70, 0xD0F89791), int64(0xC76C51A3, 0x0654BE30), 
	int64(0xD192E819, 0xD6EF5218), int64(0xD6990624, 0x5565A910),
	int64(0xF40E3585, 0x5771202A), int64(0x106AA070, 0x32BBD1B8), 
	int64(0x19A4C116, 0xB8D2D0C8), int64(0x1E376C08, 0x5141AB53),
	int64(0x2748774C, 0xDF8EEB99), int64(0x34B0BCB5, 0xE19B48A8), 
	int64(0x391C0CB3, 0xC5C95A63), int64(0x4ED8AA4A, 0xE3418ACB),
	int64(0x5B9CCA4F, 0x7763E373), int64(0x682E6FF3, 0xD6B2B8A3), 
	int64(0x748F82EE, 0x5DEFB2FC), int64(0x78A5636F, 0x43172F60),
	int64(0x84C87814, 0xA1F0AB72), int64(0x8CC70208, 0x1A6439EC), 
	int64(0x90BEFFFA, 0x23631E28), int64(0xA4506CEB, 0xDE82BDE9),
	int64(0xBEF9A3F7, 0xB2C67915), int64(0xC67178F2, 0xE372532B), 
	int64(0xCA273ECE, 0xEA26619C), int64(0xD186B8C7, 0x21C0C207),
	int64(0xEADA7DD6, 0xCDE0EB1E), int64(0xF57D4F7F, 0xEE6ED178), 
	int64(0x06F067AA, 0x72176FBA), int64(0x0A637DC5, 0xA2C898A6),
	int64(0x113F9804, 0xBEF90DAE), int64(0x1B710B35, 0x131C471B), 
	int64(0x28DB77F5, 0x23047D84), int64(0x32CAAB7B, 0x40C72493),
	int64(0x3C9EBE0A, 0x15C9BEBC), int64(0x431D67C4, 0x9C100D4C), 
	int64(0x4CC5D4BE, 0xCB3E42B6), int64(0x597F299C, 0xFC657E2A),
	int64(0x5FCB6FAB, 0x3AD6FAEC), int64(0x6C44198C, 0x4A475817)
];

/**
 * Calculate a hash based on 64-bit words
 *
 * @param data - The data to hash
 * @param hash - The initial hash value
 */
function sha64(bytes: ByteBuffer, _hash: number[]): ByteBuffer {
	let numBits = bytes.length * 8;
	const words = bytesToWords(bytes);

	// Initialize the hash
	const hash: Int64[] = [];
	for (let i = 0, count = _hash.length; i < count; i += 2) {
		hash.push(int64(_hash[i], _hash[i + 1]));
	}

	// Initialize state variables
	const T1 = int64(0, 0);
	const T2 = int64(0, 0);
	const a = int64(0, 0);
	const b = int64(0, 0);
	const c = int64(0, 0);
	const d = int64(0, 0);
	const e = int64(0, 0);
	const f = int64(0, 0);
	const g = int64(0, 0);
	const h = int64(0, 0);
	const s0 = int64(0, 0);
	const s1 = int64(0, 0);
	const Ch = int64(0, 0);
	const Maj = int64(0, 0);
	const r1 = int64(0, 0);
	const r2 = int64(0, 0);
	const r3 = int64(0, 0);

	const w = new Array(80);
	for (let i = 0; i < 80; i++) {
		w[i] = int64(0, 0);
	}

	// Pad the input
	words[numBits >> 5] |= 0x80 << (24 - numBits % 32);
	words[((numBits + 128 >> 10) << 5) + 31] = numBits;

	let numWords = words.length;
	for (let i = 0; i < numWords; i += 32) {
		copy(a, hash[0]);
		copy(b, hash[1]);
		copy(c, hash[2]);
		copy(d, hash[3]);
		copy(e, hash[4]);
		copy(f, hash[5]);
		copy(g, hash[6]);
		copy(h, hash[7]);

		for (let j = 0; j < 16; j++) {
			w[j][1] = words[i + 2 * j];
			w[j][0] = words[i + 2 * j + 1];
		}

		for (let j = 16; j < 80; j++) {
			// sigma1
			rotateRight(r1, w[j - 2], 19);
			reverseRotateRight(r2, w[j - 2], 29);
			shiftRight(r3, w[j - 2], 6);
			s1[0] = r1[0] ^ r2[0] ^ r3[0];
			s1[1] = r1[1] ^ r2[1] ^ r3[1];

			// sigma0
			rotateRight(r1, w[j - 15], 1);
			rotateRight(r2, w[j - 15], 8);
			shiftRight(r3, w[j - 15], 7);
			s0[0] = r1[0] ^ r2[0] ^ r3[0];
			s0[1] = r1[1] ^ r2[1] ^ r3[1];

			add4(w[j], s1, w[j - 7], s0, w[j - 16]);
		}

		for (let j = 0; j < 80; j++) {
			// Ch
			Ch[0] = (e[0] & f[0]) ^ (~e[0] & g[0]);
			Ch[1] = (e[1] & f[1]) ^ (~e[1] & g[1]);

			// Sigma1
			rotateRight(r1, e, 14);
			rotateRight(r2, e, 18);
			reverseRotateRight(r3, e, 9);
			s1[0] = r1[0] ^ r2[0] ^ r3[0];
			s1[1] = r1[1] ^ r2[1] ^ r3[1];

			// Sigma0
			rotateRight(r1, a, 28);
			reverseRotateRight(r2, a, 2);
			reverseRotateRight(r3, a, 7);
			s0[0] = r1[0] ^ r2[0] ^ r3[0];
			s0[1] = r1[1] ^ r2[1] ^ r3[1];

			//Maj
			Maj[0] = (a[0] & b[0]) ^ (a[0] & c[0]) ^ (b[0] & c[0]);
			Maj[1] = (a[1] & b[1]) ^ (a[1] & c[1]) ^ (b[1] & c[1]);

			add5(T1, h, s1, Ch, K[j], w[j]);
			add(T2, s0, Maj);

			copy(h, g);
			copy(g, f);
			copy(f, e);
			add(e, d, T1);
			copy(d, c);
			copy(c, b);
			copy(b, a);
			add(a, T1, T2);
		}

		add(hash[0], hash[0], a);
		add(hash[1], hash[1], b);
		add(hash[2], hash[2], c);
		add(hash[3], hash[3], d);
		add(hash[4], hash[4], e);
		add(hash[5], hash[5], f);
		add(hash[6], hash[6], g);
		add(hash[7], hash[7], h);
	}

	//	convert the final hash back to 32-bit words
	let ret: number[] = [];
	const count = hash.length;
	for (let i = 0; i < count; i++) {
		ret[i * 2] = hash[i][1];
		ret[i * 2 + 1] = hash[i][0];
	}

	return wordsToBytes(ret);
};

const HASH_384 = [
	0xCBBB9D5D, 0xC1059ED8, 0x629A292A, 0x367CD507, 0x9159015A, 0x3070DD17, 0x152FECD8, 0xF70E5939,
	0x67332667, 0xFFC00B31, 0x8EB44A87, 0x68581511, 0xDB0C2E0D, 0x64F98FA7, 0x47B5481D, 0xBEFA4FA4
];
const sha384 = <ScriptHash> function (data: ByteBuffer): ByteBuffer {
	const hash = sha64(data, HASH_384);
	return hash.slice(0, hash.length - 16);
};
sha384.blockSize = 1024;
export { sha384 };

const HASH_512: number[] = [
	0x6A09E667, 0xF3BCC908, 0xBB67AE85, 0x84CAA73B, 0x3C6EF372, 0xFE94F82B, 0xA54FF53A, 0x5F1D36F1,
	0x510E527F, 0xADE682D1, 0x9B05688C, 0x2B3E6C1F, 0x1F83D9AB, 0xFB41BD6B, 0x5BE0CD19, 0x137E2179
];
const sha512 = <ScriptHash> function (data: ByteBuffer): ByteBuffer {
	return sha64(data, HASH_512);
}
sha512.blockSize = 1024;
export { sha512 };
