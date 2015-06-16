import { add } from 'dojo-core/has';

add('webcrypto', typeof global.SubtleCrypto !== 'undefined');

export { cache, add, default} from 'dojo-core/has';
