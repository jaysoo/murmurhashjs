Node.js binding for MurmurHash2A by Austin Appleby. 

This is a very fast, non-cryptographic hash suitable for general
hash-based lookup. See: http://sites.google.com/site/murmurhash/

Build with ``node-waf configure build``

murmurhash.js exports two versions of MurmurHash2A: the regular
version (MurmurHash2A) and the incremental version (CMurmurHash2A).

Usage:

```js
  var assert = require('assert')
    , murmurhash = require('./murmurhash');

  var hash = murmurhash.MurmurHash('foobar'); 

  var hasher = murmurhash.createMurmurHasher();
  hasher.add("foo");
  hasher.add("bar");
  var chash = hasher.end();

  assert.equal(hash, chash);
```

Also see tests.js

Licensed under MIT license. See LICENSE
