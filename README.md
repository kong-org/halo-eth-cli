# CLI tool for HaLo Chips

## V1 Commands
### `sign <key_no> <hash>`
Sign 32 byte long, hex encoded `hash` of data using key designated by `key_no` (range: 1-3).

**Example:**
Sign `139e33f550dfd817805425693f5a33a499fd6b153f8b7ee749fd71fb978debe1` using key #1:
```
>>> node cli.js sign 1 139e33f550dfd817805425693f5a33a499fd6b153f8b7ee749fd71fb978debe1
{
  sig: '304402204ce3edfd5f0425a8d97139bd7cc70ceb681f845f4f4c6a0e77e0d90221974bf40220495385b599113048a989e02259994e674ba16877e2d5df2c601214ddfafccc27'
}
```

### `pkeys`
Read public keys out of the tag:
```
>>> node cli.js pkeys
{
  pkey1: '04bc2c966ea37f4cfe76c7af3c2df5853cecc3dca06c1a21044266319d9ab513d1de8a2ef8f72c6001472ec4a81aa40e08f109380b934ca211e63d64f556d7f30a',
  pkey2: '04ae9276076cb7fb1374af26df32d1319c5cdd031d739d79df2b819579f48d9f8028b6955918fd8521e8c80ba2bc4dbb80305ef72214679b2a42aad049eb084bd9',
  pkey3: '04fb0f3b0ecf7080a46eac4fa67bb33357de05d012388eeefb2a9ca92349b0ce95cd0d858c469e4d3f9b4f9ffa61cc221e98818652688cfa7fe5d5675c0641db25'
}
```

### `keygen`
Request generation of the 3rd private key.
```
node cli.js keygen
```

## V2 Commands
V2 is backwards compatible but also supports the following additional commands:

### `info`
Read all possible information from the tag (data latches, public keys, attestation).
Verify attestation and check if public keys are operational.

Example:
```
>>> node cli.js info
{
  tagVersion: 'c2',
  issuer: {
    name: 'Airtime Network Inc. Attestation key #0',
    publicKey: '0436de4602f2d85d9cbd4deac220173b4e9f32aae7e808278aa34d6c6a88482b4353b22e017b02427a5f8b71d042c0a444886169ef09371652a33504c834f0aff9'
  },
  tagBuiltinKeys: {
    publicKey1: '04bc2c966ea37f4cfe76c7af3c2df5853cecc3dca06c1a21044266319d9ab513d1de8a2ef8f72c6001472ec4a81aa40e08f109380b934ca211e63d64f556d7f30a',
    publicKey2: '04ae9276076cb7fb1374af26df32d1319c5cdd031d739d79df2b819579f48d9f8028b6955918fd8521e8c80ba2bc4dbb80305ef72214679b2a42aad049eb084bd9'
  },
  tagAdditionalKeys: {
    publicKey3: '04fb0f3b0ecf7080a46eac4fa67bb33357de05d012388eeefb2a9ca92349b0ce95cd0d858c469e4d3f9b4f9ffa61cc221e98818652688cfa7fe5d5675c0641db25'
  },
  latches: {
    latch1: null,
    latch2: '1cc48a135720a8d1966dec8cf43cc22793fd7835e2e00e6436626c43ce94d54f'
  },
  attestSignature: '304502210099a8bfdd3d3ece98cd6d6abbe904a6e9ccdb263cc81f2982b14aa288d018e107022040becd11ac72d98a22a38a39f7573c3408ed42a5d4d2b8ad443fc5b606ea3365',
  _: 'We have verified that the issuer signature is correct and the tag is able to sign data using these keys.'
}
```

### `store <slot_id> <data>`
Store 32 byte long, hex encoded `data` in latch slot designated by `slot_id` (range: 1-2).

**Caution:** After data is stored into certain slot, this slot can not be modified anymore!

```
>>> node cli.js store 2 1cc48a135720a8d1966dec8cf43cc22793fd7835e2e00e6436626c43ce94d54f
{ success: true, message: 'Latch data was written succesfully.' }
```