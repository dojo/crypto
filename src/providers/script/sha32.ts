import { ByteBuffer, utf8 } from 'dojo-core/encoding';
import Promise from 'dojo-core/Promise';
import { ScriptHash, addWords, bytesToWords, wordsToBytes } from './base';
import { Data } from '../../crypto';

// Encoding functions
function S (X: number, n: number): number { return ( X >>> n ) | (X << (32 - n)); }
function R (X: number, n: number): number { return ( X >>> n ); }
function Ch(x: number, y: number, z: number): number  { return ((x & y) ^ ((~x) & z)); }
function Maj(x: number, y: number, z: number): number { return ((x & y) ^ (x & z) ^ (y & z)); }
function Sigma0(x: number): number { return (S(x,  2) ^ S(x, 13) ^ S(x, 22)); }
function Sigma1(x: number): number { return (S(x,  6) ^ S(x, 11) ^ S(x, 25)); }
function Gamma0(x: number): number { return (S(x,  7) ^ S(x, 18) ^ R(x,  3)); }
function Gamma1(x: number): number { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }

const K = [
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
];

/**
 * Calculate a hash based on 32-bit words
 *
 * @param data - The data to hash
 * @param hash - The initial hash value
 */
function sha32(bytes: ByteBuffer, hash: number[]): ByteBuffer {
	let numBits = bytes.length * 8;
	const words = bytesToWords(bytes);

	// Clone the initial hash since we'll be writing the output into this.
	hash = hash.slice();

	// Pad the input
	words[numBits >> 5] |= 0x80 << (24 - numBits % 32);
	words[((numBits + 64 >> 9) << 4) + 15] = numBits;

	const w = new Array(64);

	// Do the digest
	let numWords = words.length;
	for (let i = 0; i < numWords; i += 16) {
		let a = hash[0];
		let b = hash[1];
		let c = hash[2];
		let d = hash[3];
		let e = hash[4];
		let f = hash[5];
		let g = hash[6];
		let h = hash[7];

		for (let j = 0; j < 64; j++) {
			if (j < 16){
				w[j] = words[j + i];
			}
			else { 
				w[j] = addWords(Gamma1(w[j - 2]), w[j - 7], Gamma0(w[j - 15]), w[j - 16]);
			}

			const T1 = addWords(h, Sigma1(e), Ch(e, f, g), K[j], w[j]);
			const T2 = addWords(Sigma0(a), Maj(a, b, c));

			h = g;
			g = f;
			f = e;
			e = addWords(d, T1);
			d = c;
			c = b;
			b = a;
			a = addWords(T1, T2);
		}

		hash[0] = addWords(a, hash[0]);
		hash[1] = addWords(b, hash[1]);
		hash[2] = addWords(c, hash[2]);
		hash[3] = addWords(d, hash[3]);
		hash[4] = addWords(e, hash[4]);
		hash[5] = addWords(f, hash[5]);
		hash[6] = addWords(g, hash[6]);
		hash[7] = addWords(h, hash[7]);
	}

	return wordsToBytes(hash);
}

const HASH_224: number[] = [
	0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
	0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
];
const sha224 = <ScriptHash> function (data: ByteBuffer): ByteBuffer {
	const hash = sha32(data, HASH_224);
	return hash.slice(0, hash.length - 4);
};
sha224.blockSize = 512;
export { sha224 };

const HASH_256: number[] = [
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
];
const sha256 = <ScriptHash> function (data: ByteBuffer): ByteBuffer {
	return sha32(data, HASH_256);
}
sha256.blockSize = 512;
export { sha256 };
