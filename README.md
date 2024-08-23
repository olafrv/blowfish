# Blowfish v1 and v2 Cipher Algorithm in Java

**Dec, 2009**: The Blowfish cipher algorithm is a symmetric-key block cipher designed by 
Bruce Schneier. Originally, v1 operates on 64-bit blocks and supports key 
sizes from 32 bits to 448 bits. It is known for its efficiency and strong
security.

**Aug, 2024**: The Blowfish v2 cipher algorithm is similar to v2, but operates on 128-bit
blocks and supports key sizes from 64 bits to 4224 bits. This v2 implementation
could be probably improved using [java.math.BigInteger](https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html) from Java, but there are a few drawbacks that is why I decided to use a custom UInt128 monad-like class for easyness.

## Usage
```bash
make 
make run    # same as make, runs examples
make clean  # delete all .class in subfolders
make test   # requires Gradle, Gradle Wapper, JUnit
```

## References

### Blowfish v1

* [Bruce Schneier's Paper on Blowfish](https://www.schneier.com/paper-blowfish-fse.html)
* [Dr. Herong Yang's Blowfish Cipher Tutorial](https://www.herongyang.com/crypto/cipher_blowfish.html)
* [Blowfish Cipher on Wikipedia](https://en.wikipedia.org/wiki/Blowfish_\(cipher\))
* [Cryptographic Padding Techniques](https://www.di-mgt.com.au/cryptopad.html)

### Blowfish v2 (Lost & Found)

* https://github.com/robistruck/blowfish2
* https://github.com/erwanmilon/blowfish2/blob/main/blowfish2.c
* https://github.com/MikeVangrouss/BLOWFISH2/blob/main/blowfish2.c
* https://gitlab.com/freepascal.org/fpc/source/-/blob/main/packages/fcl-base/src/blowfish2.pp

### Dev Environment

* https://code.visualstudio.com/docs/java/java-project
* https://docs.gradle.org/current/userguide/installation.html#ex-installing-manually
* https://github.com/junit-team/junit5-samples/blob/r5.11.0/junit5-jupiter-starter-gradle/build.gradle
* https://docs.gradle.org/current/dsl/org.gradle.api.tasks.testing.Test.html
* https://symflower.com/en/company/blog/2023/running-junit-tests-with-gradle/
* https://junit.org/junit5/docs/current/user-guide/
* https://code.visualstudio.com/docs/java/java-project