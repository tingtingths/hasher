# hasher

Python hashlib wrapper. Runs on Python 3.6 or above.

```shell
$ hasher -h
usage: hasher [-h] [--version] [-c [CHECKSUM_FILE]] [--progress] [-p [PARALLEL]]
              {blake2s,sha3_512,shake_128,sha3_224,whirlpool,sha3_384,sha384,blake2b,sha224,sha1,ripemd160,sm3,sha512,sha256,sha3_256,mdc2,md5,sha512_224,md5-sha1,sha512_256,shake_256,md4}
              [input [input ...]]

hash files.

positional arguments:
  {blake2s,sha3_512,shake_128,sha3_224,whirlpool,sha3_384,sha384,blake2b,sha224,sha1,ripemd160,sm3,sha512,sha256,sha3_256,mdc2,md5,sha512_224,md5-sha1,sha512_256,shake_256,md4}
                        one of these hash algorithms
  input                 file path, omit if reading from stdin

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -c [CHECKSUM_FILE], --checksum_file [CHECKSUM_FILE]
                        checksum file to check against
  --progress            print progress bar to stderr
  -p [PARALLEL], --parallel [PARALLEL]
                        parallel count
```