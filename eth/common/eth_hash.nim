# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## keccak256 is used across ethereum as the "default" hash function and this
## module provides a type and some helpers to produce such hashes

import std/hashes
import nimcrypto/[keccak, utils]
import nimcrypto/hash except `$`

from nimcrypto/utils import bytesToHex

export
  keccak.update, keccak.finish, hash.fromHex, hash.toDigest, hashes.Hash

type
  KeccakHash* = MDigest[256]
    ## A hash value computed using keccak256
    ## note: this aliases Eth2Digest too, which uses a different hash function!

template withKeccakHash*(body: untyped): KeccakHash =
  ## This little helper will init the hash function and return the sliced
  ## hash:
  ## let hashOfData = withHash: h.update(data)
  block:
    var h {.inject.}: keccak256
    # init(h) # not needed for new instance
    body
    finish(h)

func keccakHash*(input: openArray[byte]): KeccakHash {.noinit.} =
    # We use the init-update-finish interface to avoid
    # the expensive burning/clearing memory (20~30% perf)
    var ctx: keccak256
    ctx.update(input)
    ctx.finish()

func keccakHash*(input: openArray[char]): KeccakHash {.noinit.} =
  keccakHash(input.toOpenArrayByte(0, input.high()))

func keccakHash*(a, b: openArray[byte]): KeccakHash =
  withKeccakHash:
    h.update a
    h.update b

func `$`*(v: KeccakHash): string =
  var res = newString((len(v.data) shl 1))
  discard bytesToHex(v.data, res, {HexFlags.LowerCase})
  res

template hash*(x: KeccakHash): Hash =
  ## Hash for digests for Nim hash tables
  # digests are already good hashes
  var h {.noinit.}: Hash
  copyMem(addr h, unsafeAddr x.data[0], static(sizeof(Hash)))
  h

func `==`*(a, b: KeccakHash): bool =
  when nimvm:
    a.data == b.data
  else:
    # nimcrypto uses a constant-time comparison for all MDigest types which for
    # KeccakHash is unnecessary - the type should never hold a secret!
    equalMem(unsafeAddr a.data[0], unsafeAddr b.data[0], sizeof(a.data))
