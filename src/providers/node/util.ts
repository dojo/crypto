import * as encoding from 'dojo-core/encoding';

/**
 * Returns the name of a Node encoding scheme that corresponds to a particular Codec. Exported for use by other node
 * provider modules.
 */
export function getEncodingName(codec?: encoding.Codec): string {
	switch (codec) {
	case encoding.ascii:
		return 'ascii';
	case encoding.utf8:
		return 'utf8';
	case encoding.base64:
		return 'base64';
	case encoding.hex:
		return 'hex';
	}
}
