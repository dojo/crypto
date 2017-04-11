# dojo-crypto

The crypto package provides cryptographic utilities including hashing and signing functions.

## Features

Coming soon!

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

© 2017 JS Foundation & contributors. [New BSD](http://opensource.org/licenses/BSD-3-Clause) license.
