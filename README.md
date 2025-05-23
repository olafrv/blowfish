# Blowfish v1 and v2 Cipher Algorithm in Java

**Dec, 2009**: The Blowfish cipher algorithm is a symmetric-key block cipher designed by 
Bruce Schneier. Originally, v1 operates on 64-bit blocks and supports key 
sizes from 32 bits to 448 bits. It is known for its efficiency and strong
security.

**Aug, 2024**: The Blowfish v2 cipher algorithm is similar to v1, but operates on 128-bit
blocks and supports key sizes from 64 bits to 4224 bits. This v2 implementation
could be probably improved using [java.math.BigInteger](https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html) from Java, but there are a few drawbacks that is why I decided to use a custom UInt128 monad-like class for easyness. Added support
for keys from 1 to 512 bytes. But recommendation is to use at least 8 bytes.

## Usage
```bash
make 
make run    # same as make, runs examples
make clean  # delete all .class in subfolders
make test   # requires Gradle, Gradle Wapper, JUnit
```

## Output

```bash
find ./src/main/java -name '*.class' -exec rm -f {} \; 
javac -classpath ./src/main/java ./src/main/java/*.java
java -classpath ./src/main/java BlowfishExample

--- Blowfish1 ---
Message Text ..... (8 bytes): ''
Message Hex ...... (8 bytes): '1111111111111111'
Key .............. (8 bytes): '0123456789ABCDEF'
Enc Hex ---------- (16 bytes): '61F9C3802281B096FD4590C8E4BB88CC'
Enc Hex Exp ...... (16 bytes): '61F9C3802281B096FD4590C8E4BB88CC'
Enc Hex Match .... (true)
Decrypted Text ... (8 bytes): ''
Decrypted Hex .... (8 bytes): '1111111111111111'

Message Text ..... (8 bytes): '�\P�(�'
Message Hex ...... (8 bytes): '1D9D5C5018F728C2'
Key .............. (8 bytes): '018310DC409B26D6'
Enc Hex ---------- (16 bytes): 'D1ABB290658BC778EBDB30A09313234C'
Enc Hex Exp ...... (16 bytes): 'D1ABB290658BC778EBDB30A09313234C'
Enc Hex Match .... (true)
Decrypted Text ... (8 bytes): '�\P�(�'
Decrypted Hex .... (8 bytes): '1D9D5C5018F728C2'

Message Text ..... (18 bytes): 'This is a test !!!'
Message Hex ...... (18 bytes): '546869732069732061207465737420212121'
Key .............. (8 bytes): '0000000000000000'
Enc Hex ---------- (24 bytes): 'D03A88D68530DF48C9542821F4A7C3325244EC722E74954A'
Enc Hex Exp ...... (24 bytes): 'D03A88D68530DF48C9542821F4A7C3325244EC722E74954A'
Enc Hex Match .... (true)
Decrypted Text ... (18 bytes): 'This is a test !!!'
Decrypted Hex .... (18 bytes): '546869732069732061207465737420212121'

Remember that before encryption message is padded to 8 multiple.
java -classpath ./src/main/java Blowfish2Example

--- Blowfish2 ---
Message Text ..... (16 bytes): ''
Message Hex ...... (16 bytes): '00000000000000010000000000000002'
Key Hex .......... (7 bytes): '544553544B4559'
Enc Hex ---------- (32 bytes): '7B2B9DE71D1B1C6291C230351177BEE8DF6A89FA5A585F4275EF5156AAF05519'
Enc Hex Exp ...... (32 bytes): '7B2B9DE71D1B1C6291C230351177BEE8DF6A89FA5A585F4275EF5156AAF05519'
Enc Hex Match .... (true)
Decrypted Text ... (16 bytes): ''
Decrypted Hex .... (16 bytes): '00000000000000010000000000000002'

Message Text ..... (16 bytes): ''
Message Hex ...... (16 bytes): '01020304050607080910111213141516'
Key Hex .......... (1 bytes): '41'
Enc Hex ---------- (32 bytes): 'CA38165603F9915C61F0776A0F55E8072AD9F5D255AB59B033F1E26A7E573B8E'
Enc Hex Exp ...... (32 bytes): 'CA38165603F9915C61F0776A0F55E8072AD9F5D255AB59B033F1E26A7E573B8E'
Enc Hex Match .... (true)
Decrypted Text ... (16 bytes): ''
Decrypted Hex .... (16 bytes): '01020304050607080910111213141516'

Message Text ..... (16 bytes): ''
Message Hex ...... (16 bytes): '01020304050607080910111213141516'
Key Hex .......... (1 bytes): '42'
Enc Hex ---------- (32 bytes): 'D07690A78B1099838DDF85826F2366C21C37A1FF3B0DD7B17164C3860609C5FB'
Enc Hex Exp ...... (32 bytes): 'D07690A78B1099838DDF85826F2366C21C37A1FF3B0DD7B17164C3860609C5FB'
Enc Hex Match .... (true)
Decrypted Text ... (16 bytes): ''
Decrypted Hex .... (16 bytes): '01020304050607080910111213141516'

Message Text ..... (18 bytes): 'This is a test !!!'
Message Hex ...... (18 bytes): '546869732069732061207465737420212121'
Key Hex .......... (16 bytes): '00000000000000000000000000000000'
Enc Hex ---------- (32 bytes): 'AF53A4C34749E843E30E847A0EAF2D180048C58FEFA58D7F5421595429C21281'
Enc Hex Exp ...... (32 bytes): 'AF53A4C34749E843E30E847A0EAF2D180048C58FEFA58D7F5421595429C21281'
Enc Hex Match .... (true)
Decrypted Text ... (18 bytes): 'This is a test !!!'
Decrypted Hex .... (18 bytes): '546869732069732061207465737420212121'

Message Text ..... (43 bytes): 'This is a much longer test 😊😊😊 !!!'
Message Hex ...... (43 bytes): '546869732069732061206D756368206C6F6E676572207465737420F09F988AF09F988AF09F988A20212121'
Key Hex .......... (16 bytes): '31323334353637383132333435363738'
Enc Hex ---------- (48 bytes): '410529C1A9A27BDFD1638687471255FD6177EFD8BCF2DD6F83A276752532F2714B366AE942234EBBF5BA90DAEFED6B06'
Enc Hex Exp ...... (48 bytes): '410529C1A9A27BDFD1638687471255FD6177EFD8BCF2DD6F83A276752532F2714B366AE942234EBBF5BA90DAEFED6B06'
Enc Hex Match .... (true)
Decrypted Text ... (43 bytes): 'This is a much longer test 😊😊😊 !!!'
Decrypted Hex .... (43 bytes): '546869732069732061206D756368206C6F6E676572207465737420F09F988AF09F988AF09F988A20212121'

Remember that before encryption message is padded to 16 bytes multiple.
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
