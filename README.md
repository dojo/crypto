# dojo-crypto

The crypto package provides cryptographic utilities including hashing and signing functions.

## Features

Currently the crypto package provides a suite of hashing functions and an HMAC implementation.

### Hashing

```ts
import getHash from 'dojo-crypto/hash';
import WritableStream from 'dojo-core/streams/WritableStream';

const sha1 = getHash('sha1');

// Hash strings
sha1('this is a test').then(function (result) {
	console.log('got hash:', result);
});
sha1('this is another test').then(function (result) {
	console.log('got hash:', result);
});

// Hash a stream
let sha1Hasher = sha1.create();
sha1Hasher.write('this is a test');
sha1Hasher.close();
sha1Hasher.digest.then(function (result) {
	console.log(got hash:', result);
});

// Use a hasher as a WritableStream sink
sha1Hasher = sha1.create();
const stream = new WritableStream<string>(sha1Hasher);
stream.write('this is a test');
stream.close();
sha1Hasher.digest.then(function (result) {
	console.log(got hash:', result);
});
```

### Signing

```ts
import sha1 from 'dojo-crypto/hash';
import getSign, { Key } from 'dojo-crypto/sign';
import WritableStream from 'dojo-core/streams/WritableStream';

const hmac = getSign('hmac');
const key: Key = {
	algorithm: 'sha1',
	data: 'foo'
};

// Generate signatures for strings
hmac(key, 'this is a test').then(function (result) {
	console.log('got HMAC:', result);
});
hmac(key, 'this is another test').then(function (result) {
	console.log('got HMAC:', result);
});

// Generate a signature for a stream
let hmacSigner = hmac.create(key);
hmacSigner.write('this is a test');
hmacSigner.close();
hmacSigner.signature.then(function (result) {
	console.log(got hash:', result);
});

// Use a signer as a WritableStreams sink
hmacSigner = hmac.create(key);
const stream = new WritableStream<string>(hmacSigner);
stream.write('this is a test');
stream.close();
hmacSigner.signature.then(function (result) {
	console.log(got hash:', result);
});
```

## How do I use this package?

Users will need to download and compile directly from this repository and
[dojo/core](https://github.com/dojo/core) for the time being. Precompiled
AMD/CommonJS modules will be provided in the future as our release tools are
improved.

Once you've downloaded `dojo-core` and `dojo-crypto`, perform the following
steps:

```sh
cd dojo-core
grunt dist
cd dist
npm link
cd ../../dojo-crypto
npm install
npm link dojo-core
```

To use a hash or signing algorithm, simply import the desired algorithm(s) from
`dojo-crypto/hash` (and `dojo-crypto/sign` if required) in your code. A default
crypto provider is selected when the library is loaded, either `node`,
`webcrypto`, or `script`. The end user may select a different provider by
importing `provider` from `dojo-crypto/main` and setting it to a new value.

## How do I contribute?

We appreciate your interest!  Please see the [Guidelines Repository](https://github.com/dojo/guidelines#readme) for the
Contributing Guidelines and Style Guide.

## Testing

Test cases MUST be written using Intern using the Object test interface and
Assert assertion interface.

90% branch coverage MUST be provided for all code submitted to this repository,
as reported by istanbul’s combined coverage results for all supported
platforms.

## Licensing information

© 2004–2015 Dojo Foundation & contributors. [New BSD](http://opensource.org/licenses/BSD-3-Clause) license.
