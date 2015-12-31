import { add } from 'dojo-core/has';
import global  from 'dojo-core/global';

add('webcrypto', typeof global.SubtleCrypto !== 'undefined');
add('typedarray', typeof global.ArrayBuffer !== 'undefined');

export { cache, add, default } from 'dojo-core/has';
