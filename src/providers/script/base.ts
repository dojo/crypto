/**
 * Notation:
 *   - A "word" is a 32-bit interger
 */
import { ByteBuffer } from 'dojo-core/encoding';

/**
 * A script hash function
 */
export interface ScriptHash {
	(data: ByteBuffer): ByteBuffer;
	blockSize: number;
}

/**
 * A general math function
 */
export interface MathFunction {
	(...inputs: number[]): number
}

/**
 * Add a list of words, with rollover
 */
export function addWords(...words: number[]): number {
	const numWords = words.length;
	let sum = words[0];
	for (let i = 1; i < numWords; i++) {
		const a = sum;
		const b = words[i];
		const low = (a & 0xFFFF) + (b & 0xFFFF);
		const high = (a >> 16) + (b >> 16) + (low >> 16);
		sum = (high << 16) | (low & 0xFFFF);
	}
	return sum;
}

/**
 * Specify the endian-ness of a integer values
 */
export enum Endian {
	Little = 0,
	Big = 1
}

/**
 * Convert an array of bytes to an array of 32-bit words. Words are assumed to be encoded in little-endian format (low
 * bytes are at lower indices).
 */
export function bytesToWords(bytes: ByteBuffer, endian: Endian = Endian.Big): number[] {
	const numWords = Math.ceil(bytes.length / 4);
	const words = new Array(numWords);

	const s0 =  0 + 24 * endian;
	const s1 =  8 +  8 * endian;
	const s2 = 16 -  8 * endian;
	const s3 = 24 - 24 * endian;

	for (let i = 0; i < numWords; i++) {
		const j = 4 * i;
		words[i] = 
			(bytes[j]     << s0) |
			(bytes[j + 1] << s1) |
			(bytes[j + 2] << s2) |
			(bytes[j + 3] << s3);
	}
	return words;
}

/**
 * Convert an array of 32-bit words to an array of bytes. Words are encoded in big-endian format (high bytes are at
 * lower indices).
 */
export function wordsToBytes(words: number[], endian: Endian = Endian.Big): number[] {
	const numWords = words.length;
	const bytes = new Array(numWords * 4);

	const s0 =  0 + 24 * endian;
	const s1 =  8 +  8 * endian;
	const s2 = 16 -  8 * endian;
	const s3 = 24 - 24 * endian;

	for (let i = 0; i < numWords; i++) {
		const word = words[i];
		const j = 4 * i;
		bytes[j]     = (word >> s0) & 0x0FF;
		bytes[j + 1] = (word >> s1) & 0x0FF;
		bytes[j + 2] = (word >> s2) & 0x0FF;
		bytes[j + 3] = (word >> s3) & 0x0FF;
	}
	return bytes;
}
