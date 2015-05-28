import registerSuite = require('intern!object');
import assert = require('intern/chai!assert');
import * as hash from 'src/hash';

registerSuite({
	name: 'hash',

	sha1() {
		hash.sha1('testing');
	}
});
