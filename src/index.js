/* @flow */

// -- Type Defs

type Decoded = {
  code: number,
  name: string,
  length: number,
  digest: Buffer
}

// -- Helper Functions

function invert (map) {
  const reverse = new Map()

  for (let key of map.keys()) {
    reverse.set(map.get(key), key)
  }

  return reverse
}

// -- Export

const mh = module.exports = function (hashOrDigest: Buffer, hashfn: string | number, length: number): Buffer | Decoded {
  if (hashOrDigest == null) {
    throw new Error('multihash must be called with the encode or decode parameters.')
  }

  if (hashfn != null) {
    return mh.encode(hashOrDigest, hashfn, length)
  }

  return mh.decode(hashOrDigest)
}

// -- Multihash Tables

mh.names = new Map({
  'sha1': 0x11,
  'sha2-256': 0x12,
  'sha2-512': 0x13,
  'sha3': 0x14,
  'blake2b': 0x40,
  'blake2s': 0x41
})

mh.codes = invert(mh.names)

mh.defaultLengths = new Map([
  [0x11, 20],
  [0x12, 32],
  [0x13, 64],
  [0x14, 64],
  [0x40, 64],
  [0x41, 3],
])

// -- Functions

mh.encode = function MultihashEncode (digest: Buffer, hashfn: string | number, length: number): Buffer {
  if (!digest || !hashfn) {
    throw new Error('multihash encode requires at least two args: hashfn, digest')
  }

  // ensure it's a hashfunction code.
  hashfn = mh.coerceCode(hashfn)

  if (!(Buffer.isBuffer(digest))) {
    throw new Error('digest should be a Buffer')
  }

  if (!length) {
    length = digest.length
  }

  if (length && digest.length !== length) {
    throw new Error('digest length should be equal to specified length.')
  }

  if (length > 127) {
    throw new Error('multihash does not yet support digest lengths greater than 127 bytes.')
  }

  return Buffer.concat([new Buffer([hashfn, length]), digest])
}

mh.decode = function MultihashDecode (multihash: Buffer): Decoded {
  const err = mh.validate(multihash)
  if (err) {
    throw err
  }

  const code = multihash[0]

  return {
    code: code,
    name: mh.codes.get(code),
    length: multihash[1],
    digest: multihash.slice(2)
  }
}

mh.validate = function validateMultihash (multihash: Buffer): ?Error {
  if (!(Buffer.isBuffer(multihash))) {
    return new Error('multihash must be a Buffer')
  }

  if (multihash.length < 3) {
    return new Error('multihash too short. must be > 3 bytes.')
  }

  if (multihash.length > 129) {
    return new Error('multihash too long. must be < 129 bytes.')
  }

  if (!mh.isAppCode(multihash[0]) && !mh.codes.get(multihash[0])) {
    return new Error('multihash unknown function code: 0x' + multihash[0].toString(16))
  }

  if (multihash.slice(2).length !== multihash[1]) {
    return new Error('multihash length inconsistent: 0x' + multihash.toString('hex'))
  }
}

mh.coerceCode = function coerceCode (hashfn: string | number): number {
  var code = hashfn
  if (typeof hashfn === 'string') {
    if (!mh.names.get(hashfn)) {
      throw new Error('Unrecognized hash function named: ' + hashfn)
    }
    code = mh.names.get(hashfn)
  }

  if (typeof code !== 'number') {
    throw new Error('Hash function code should be a number. Got: ' + code)
  }

  if (!mh.codes.get(code) && !mh.isAppCode(code)) {
    throw new Error('Unrecognized function code: ' + code)
  }

  return code
}

mh.isAppCode = function isAppCode (code: number): boolean {
  return code > 0 && code < 0x10
}
