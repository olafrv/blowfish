/**
 *   Blowfish.java
 *
 *   An implementation on Blowfish cipher algorithm in Java, based on:
 *    - Bruce Schneier (2009) at: http://www.schneier.com/paper-blowfish-fse.html
 *    - Dr. Herong Yang (2009) at: http://www.herongyang.com/crypto/cipher_blowfish.html 
 *    - Wikipedia (2009): http://en.wikipedia.org/wiki/Blowfish_(cipher)
 *    - DI Managment (2009): http://www.di-mgt.com.au/cryptopad.html
 *
 *   Copyright (C) Dec 23th, 2009 - Olaf Reitmaier Veracierta <olafrv@gmail.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
package Blowfish;
 
public class Blowfish{

	public Blowfish(){
                reset();
	}

        public void reset(){
                //Create (newly) the P an S boxes arrays
                P = new long[18];  
                S = new long[4][256];                
                /* Uncomment if you want to scramble P & S original arrays 
                 * because they are "static final" (not recommended)
                 */
                /*
                  P = P_ORIGINAL;
                  S[0] = S_ORIGINAL[0];
                  S[1] = S_ORIGINAL[1];                
                  S[2] = S_ORIGINAL[2];                
                  S[3] = S_ORIGINAL[3];
                */
                //Copy values from the original arrays (constant arrays)
	        System.arraycopy(P_ORIGINAL,0,P,0,18);
	        System.arraycopy(S_ORIGINAL[0],0,S[0],0,256);
	        System.arraycopy(S_ORIGINAL[1],0,S[1],0,256);
	        System.arraycopy(S_ORIGINAL[2],0,S[2],0,256);
	        System.arraycopy(S_ORIGINAL[3],0,S[3],0,256);
        }
        

	/* Constant 2^32 */
        private static long POW2TO32 = 4294967296L;

        /* State values for this Blowfish cipher */
        private static final int UNINITIALIZED = 0;  
        private static final int INITIALIZING = 1;  
        private static final int INITIALIZED = 2;  

        /* The state of the Blowfish cipher */
        private int state = UNINITIALIZED;	

        /* Char/byte values used to pad the plain text to 8 bytes mutiples */
	private static final int [] PADDING_BYTES = {0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

        private long [] P; //Will be scrambled when initialized but copied from P_ORIGINAL
        private long [][] S; //Will be scrambled when initialized but copied from S_ORIGINAL

        /* S boxes based on PI in decimal format
         * Unsigned integer of 32 bits (saved as long) derived from PI digits 
         */
        /*
         private long [][] S_ORIGINAL =  {
            {
              0xd1310ba6L, 0x98dfb5acL, 0x2ffd72dbL, 0xd01adfb7L, 0xb8e1afedL, 0x6a267e96L,
              0xba7c9045L, 0xf12c7f99L, 0x24a19947L, 0xb3916cf7L, 0x0801f2e2L, 0x858efc16L,
              0x636920d8L, 0x71574e69L, 0xa458fea3L, 0xf4933d7eL, 0x0d95748fL, 0x728eb658L,
              0x718bcd58L, 0x82154aeeL, 0x7b54a41dL, 0xc25a59b5L, 0x9c30d539L, 0x2af26013L,
              0xc5d1b023L, 0x286085f0L, 0xca417918L, 0xb8db38efL, 0x8e79dcb0L, 0x603a180eL,
              0x6c9e0e8bL, 0xb01e8a3eL, 0xd71577c1L, 0xbd314b27L, 0x78af2fdaL, 0x55605c60L,
              0xe65525f3L, 0xaa55ab94L, 0x57489862L, 0x63e81440L, 0x55ca396aL, 0x2aab10b6L,
              0xb4cc5c34L, 0x1141e8ceL, 0xa15486afL, 0x7c72e993L, 0xb3ee1411L, 0x636fbc2aL,
              0x2ba9c55dL, 0x741831f6L, 0xce5c3e16L, 0x9b87931eL, 0xafd6ba33L, 0x6c24cf5cL,
              0x7a325381L, 0x28958677L, 0x3b8f4898L, 0x6b4bb9afL, 0xc4bfe81bL, 0x66282193L,
              0x61d809ccL, 0xfb21a991L, 0x487cac60L, 0x5dec8032L, 0xef845d5dL, 0xe98575b1L,
              0xdc262302L, 0xeb651b88L, 0x23893e81L, 0xd396acc5L, 0x0f6d6ff3L, 0x83f44239L,
              0x2e0b4482L, 0xa4842004L, 0x69c8f04aL, 0x9e1f9b5eL, 0x21c66842L, 0xf6e96c9aL,
              0x670c9c61L, 0xabd388f0L, 0x6a51a0d2L, 0xd8542f68L, 0x960fa728L, 0xab5133a3L,
              0x6eef0b6cL, 0x137a3be4L, 0xba3bf050L, 0x7efb2a98L, 0xa1f1651dL, 0x39af0176L,
              0x66ca593eL, 0x82430e88L, 0x8cee8619L, 0x456f9fb4L, 0x7d84a5c3L, 0x3b8b5ebeL,
              0xe06f75d8L, 0x85c12073L, 0x401a449fL, 0x56c16aa6L, 0x4ed3aa62L, 0x363f7706L,
              0x1bfedf72L, 0x429b023dL, 0x37d0d724L, 0xd00a1248L, 0xdb0fead3L, 0x49f1c09bL,
              0x075372c9L, 0x80991b7bL, 0x25d479d8L, 0xf6e8def7L, 0xe3fe501aL, 0xb6794c3bL,
              0x976ce0bdL, 0x04c006baL, 0xc1a94fb6L, 0x409f60c4L, 0x5e5c9ec2L, 0x196a2463L,
              0x68fb6fafL, 0x3e6c53b5L, 0x1339b2ebL, 0x3b52ec6fL, 0x6dfc511fL, 0x9b30952cL,
              0xcc814544L, 0xaf5ebd09L, 0xbee3d004L, 0xde334afdL, 0x660f2807L, 0x192e4bb3L,
              0xc0cba857L, 0x45c8740fL, 0xd20b5f39L, 0xb9d3fbdbL, 0x5579c0bdL, 0x1a60320aL,
              0xd6a100c6L, 0x402c7279L, 0x679f25feL, 0xfb1fa3ccL, 0x8ea5e9f8L, 0xdb3222f8L,
              0x3c7516dfL, 0xfd616b15L, 0x2f501ec8L, 0xad0552abL, 0x323db5faL, 0xfd238760L,
              0x53317b48L, 0x3e00df82L, 0x9e5c57bbL, 0xca6f8ca0L, 0x1a87562eL, 0xdf1769dbL,
              0xd542a8f6L, 0x287effc3L, 0xac6732c6L, 0x8c4f5573L, 0x695b27b0L, 0xbbca58c8L,
              0xe1ffa35dL, 0xb8f011a0L, 0x10fa3d98L, 0xfd2183b8L, 0x4afcb56cL, 0x2dd1d35bL,
              0x9a53e479L, 0xb6f84565L, 0xd28e49bcL, 0x4bfb9790L, 0xe1ddf2daL, 0xa4cb7e33L,
              0x62fb1341L, 0xcee4c6e8L, 0xef20cadaL, 0x36774c01L, 0xd07e9efeL, 0x2bf11fb4L,
              0x95dbda4dL, 0xae909198L, 0xeaad8e71L, 0x6b93d5a0L, 0xd08ed1d0L, 0xafc725e0L,
              0x8e3c5b2fL, 0x8e7594b7L, 0x8ff6e2fbL, 0xf2122b64L, 0x8888b812L, 0x900df01cL,
              0x4fad5ea0L, 0x688fc31cL, 0xd1cff191L, 0xb3a8c1adL, 0x2f2f2218L, 0xbe0e1777L,
              0xea752dfeL, 0x8b021fa1L, 0xe5a0cc0fL, 0xb56f74e8L, 0x18acf3d6L, 0xce89e299L,
              0xb4a84fe0L, 0xfd13e0b7L, 0x7cc43b81L, 0xd2ada8d9L, 0x165fa266L, 0x80957705L,
              0x93cc7314L, 0x211a1477L, 0xe6ad2065L, 0x77b5fa86L, 0xc75442f5L, 0xfb9d35cfL,
              0xebcdaf0cL, 0x7b3e89a0L, 0xd6411bd3L, 0xae1e7e49L, 0x00250e2dL, 0x2071b35eL,
              0x226800bbL, 0x57b8e0afL, 0x2464369bL, 0xf009b91eL, 0x5563911dL, 0x59dfa6aaL,
              0x78c14389L, 0xd95a537fL, 0x207d5ba2L, 0x02e5b9c5L, 0x83260376L, 0x6295cfa9L,
              0x11c81968L, 0x4e734a41L, 0xb3472dcaL, 0x7b14a94aL, 0x1b510052L, 0x9a532915L,
              0xd60f573fL, 0xbc9bc6e4L, 0x2b60a476L, 0x81e67400L, 0x08ba6fb5L, 0x571be91fL,
              0xf296ec6bL, 0x2a0dd915L, 0xb6636521L, 0xe7b9f9b6L, 0xff34052eL, 0xc5855664L,
              0x53b02d5dL, 0xa99f8fa1L, 0x08ba4799L, 0x6e85076aL
            },
            {
              0x4b7a70e9L, 0xb5b32944L, 0xdb75092eL, 0xc4192623L, 0xad6ea6b0L, 0x49a7df7dL,
              0x9cee60b8L, 0x8fedb266L, 0xecaa8c71L, 0x699a17ffL, 0x5664526cL, 0xc2b19ee1L,
              0x193602a5L, 0x75094c29L, 0xa0591340L, 0xe4183a3eL, 0x3f54989aL, 0x5b429d65L,
              0x6b8fe4d6L, 0x99f73fd6L, 0xa1d29c07L, 0xefe830f5L, 0x4d2d38e6L, 0xf0255dc1L,
              0x4cdd2086L, 0x8470eb26L, 0x6382e9c6L, 0x021ecc5eL, 0x09686b3fL, 0x3ebaefc9L,
              0x3c971814L, 0x6b6a70a1L, 0x687f3584L, 0x52a0e286L, 0xb79c5305L, 0xaa500737L,
              0x3e07841cL, 0x7fdeae5cL, 0x8e7d44ecL, 0x5716f2b8L, 0xb03ada37L, 0xf0500c0dL,
              0xf01c1f04L, 0x0200b3ffL, 0xae0cf51aL, 0x3cb574b2L, 0x25837a58L, 0xdc0921bdL,
              0xd19113f9L, 0x7ca92ff6L, 0x94324773L, 0x22f54701L, 0x3ae5e581L, 0x37c2dadcL,
              0xc8b57634L, 0x9af3dda7L, 0xa9446146L, 0x0fd0030eL, 0xecc8c73eL, 0xa4751e41L,
              0xe238cd99L, 0x3bea0e2fL, 0x3280bba1L, 0x183eb331L, 0x4e548b38L, 0x4f6db908L,
              0x6f420d03L, 0xf60a04bfL, 0x2cb81290L, 0x24977c79L, 0x5679b072L, 0xbcaf89afL,
              0xde9a771fL, 0xd9930810L, 0xb38bae12L, 0xdccf3f2eL, 0x5512721fL, 0x2e6b7124L,
              0x501adde6L, 0x9f84cd87L, 0x7a584718L, 0x7408da17L, 0xbc9f9abcL, 0xe94b7d8cL,
              0xec7aec3aL, 0xdb851dfaL, 0x63094366L, 0xc464c3d2L, 0xef1c1847L, 0x3215d908L,
              0xdd433b37L, 0x24c2ba16L, 0x12a14d43L, 0x2a65c451L, 0x50940002L, 0x133ae4ddL,
              0x71dff89eL, 0x10314e55L, 0x81ac77d6L, 0x5f11199bL, 0x043556f1L, 0xd7a3c76bL,
              0x3c11183bL, 0x5924a509L, 0xf28fe6edL, 0x97f1fbfaL, 0x9ebabf2cL, 0x1e153c6eL,
              0x86e34570L, 0xeae96fb1L, 0x860e5e0aL, 0x5a3e2ab3L, 0x771fe71cL, 0x4e3d06faL,
              0x2965dcb9L, 0x99e71d0fL, 0x803e89d6L, 0x5266c825L, 0x2e4cc978L, 0x9c10b36aL,
              0xc6150ebaL, 0x94e2ea78L, 0xa5fc3c53L, 0x1e0a2df4L, 0xf2f74ea7L, 0x361d2b3dL,
              0x1939260fL, 0x19c27960L, 0x5223a708L, 0xf71312b6L, 0xebadfe6eL, 0xeac31f66L,
              0xe3bc4595L, 0xa67bc883L, 0xb17f37d1L, 0x018cff28L, 0xc332ddefL, 0xbe6c5aa5L,
              0x65582185L, 0x68ab9802L, 0xeecea50fL, 0xdb2f953bL, 0x2aef7dadL, 0x5b6e2f84L,
              0x1521b628L, 0x29076170L, 0xecdd4775L, 0x619f1510L, 0x13cca830L, 0xeb61bd96L,
              0x0334fe1eL, 0xaa0363cfL, 0xb5735c90L, 0x4c70a239L, 0xd59e9e0bL, 0xcbaade14L,
              0xeecc86bcL, 0x60622ca7L, 0x9cab5cabL, 0xb2f3846eL, 0x648b1eafL, 0x19bdf0caL,
              0xa02369b9L, 0x655abb50L, 0x40685a32L, 0x3c2ab4b3L, 0x319ee9d5L, 0xc021b8f7L,
              0x9b540b19L, 0x875fa099L, 0x95f7997eL, 0x623d7da8L, 0xf837889aL, 0x97e32d77L,
              0x11ed935fL, 0x16681281L, 0x0e358829L, 0xc7e61fd6L, 0x96dedfa1L, 0x7858ba99L,
              0x57f584a5L, 0x1b227263L, 0x9b83c3ffL, 0x1ac24696L, 0xcdb30aebL, 0x532e3054L,
              0x8fd948e4L, 0x6dbc3128L, 0x58ebf2efL, 0x34c6ffeaL, 0xfe28ed61L, 0xee7c3c73L,
              0x5d4a14d9L, 0xe864b7e3L, 0x42105d14L, 0x203e13e0L, 0x45eee2b6L, 0xa3aaabeaL,
              0xdb6c4f15L, 0xfacb4fd0L, 0xc742f442L, 0xef6abbb5L, 0x654f3b1dL, 0x41cd2105L,
              0xd81e799eL, 0x86854dc7L, 0xe44b476aL, 0x3d816250L, 0xcf62a1f2L, 0x5b8d2646L,
              0xfc8883a0L, 0xc1c7b6a3L, 0x7f1524c3L, 0x69cb7492L, 0x47848a0bL, 0x5692b285L,
              0x095bbf00L, 0xad19489dL, 0x1462b174L, 0x23820e00L, 0x58428d2aL, 0x0c55f5eaL,
              0x1dadf43eL, 0x233f7061L, 0x3372f092L, 0x8d937e41L, 0xd65fecf1L, 0x6c223bdbL,
              0x7cde3759L, 0xcbee7460L, 0x4085f2a7L, 0xce77326eL, 0xa6078084L, 0x19f8509eL,
              0xe8efd855L, 0x61d99735L, 0xa969a7aaL, 0xc50c06c2L, 0x5a04abfcL, 0x800bcadcL,
              0x9e447a2eL, 0xc3453484L, 0xfdd56705L, 0x0e1e9ec9L, 0xdb73dbd3L, 0x105588cdL,
              0x675fda79L, 0xe3674340L, 0xc5c43465L, 0x713e38d8L, 0x3d28f89eL, 0xf16dff20L,
              0x153e21e7L, 0x8fb03d4aL, 0xe6e39f2bL, 0xdb83adf7L
            },

            {
              0xe93d5a68L, 0x948140f7L, 0xf64c261cL, 0x94692934L, 0x411520f7L, 0x7602d4f7L,
              0xbcf46b2eL, 0xd4a20068L, 0xd4082471L, 0x3320f46aL, 0x43b7d4b7L, 0x500061afL,
              0x1e39f62eL, 0x97244546L, 0x14214f74L, 0xbf8b8840L, 0x4d95fc1dL, 0x96b591afL,
              0x70f4ddd3L, 0x66a02f45L, 0xbfbc09ecL, 0x03bd9785L, 0x7fac6dd0L, 0x31cb8504L,
              0x96eb27b3L, 0x55fd3941L, 0xda2547e6L, 0xabca0a9aL, 0x28507825L, 0x530429f4L,
              0x0a2c86daL, 0xe9b66dfbL, 0x68dc1462L, 0xd7486900L, 0x680ec0a4L, 0x27a18deeL,
              0x4f3ffea2L, 0xe887ad8cL, 0xb58ce006L, 0x7af4d6b6L, 0xaace1e7cL, 0xd3375fecL,
              0xce78a399L, 0x406b2a42L, 0x20fe9e35L, 0xd9f385b9L, 0xee39d7abL, 0x3b124e8bL,
              0x1dc9faf7L, 0x4b6d1856L, 0x26a36631L, 0xeae397b2L, 0x3a6efa74L, 0xdd5b4332L,
              0x6841e7f7L, 0xca7820fbL, 0xfb0af54eL, 0xd8feb397L, 0x454056acL, 0xba489527L,
              0x55533a3aL, 0x20838d87L, 0xfe6ba9b7L, 0xd096954bL, 0x55a867bcL, 0xa1159a58L,
              0xcca92963L, 0x99e1db33L, 0xa62a4a56L, 0x3f3125f9L, 0x5ef47e1cL, 0x9029317cL,
              0xfdf8e802L, 0x04272f70L, 0x80bb155cL, 0x05282ce3L, 0x95c11548L, 0xe4c66d22L,
              0x48c1133fL, 0xc70f86dcL, 0x07f9c9eeL, 0x41041f0fL, 0x404779a4L, 0x5d886e17L,
              0x325f51ebL, 0xd59bc0d1L, 0xf2bcc18fL, 0x41113564L, 0x257b7834L, 0x602a9c60L,
              0xdff8e8a3L, 0x1f636c1bL, 0x0e12b4c2L, 0x02e1329eL, 0xaf664fd1L, 0xcad18115L,
              0x6b2395e0L, 0x333e92e1L, 0x3b240b62L, 0xeebeb922L, 0x85b2a20eL, 0xe6ba0d99L,
              0xde720c8cL, 0x2da2f728L, 0xd0127845L, 0x95b794fdL, 0x647d0862L, 0xe7ccf5f0L,
              0x5449a36fL, 0x877d48faL, 0xc39dfd27L, 0xf33e8d1eL, 0x0a476341L, 0x992eff74L,
              0x3a6f6eabL, 0xf4f8fd37L, 0xa812dc60L, 0xa1ebddf8L, 0x991be14cL, 0xdb6e6b0dL,
              0xc67b5510L, 0x6d672c37L, 0x2765d43bL, 0xdcd0e804L, 0xf1290dc7L, 0xcc00ffa3L,
              0xb5390f92L, 0x690fed0bL, 0x667b9ffbL, 0xcedb7d9cL, 0xa091cf0bL, 0xd9155ea3L,
              0xbb132f88L, 0x515bad24L, 0x7b9479bfL, 0x763bd6ebL, 0x37392eb3L, 0xcc115979L,
              0x8026e297L, 0xf42e312dL, 0x6842ada7L, 0xc66a2b3bL, 0x12754cccL, 0x782ef11cL,
              0x6a124237L, 0xb79251e7L, 0x06a1bbe6L, 0x4bfb6350L, 0x1a6b1018L, 0x11caedfaL,
              0x3d25bdd8L, 0xe2e1c3c9L, 0x44421659L, 0x0a121386L, 0xd90cec6eL, 0xd5abea2aL,
              0x64af674eL, 0xda86a85fL, 0xbebfe988L, 0x64e4c3feL, 0x9dbc8057L, 0xf0f7c086L,
              0x60787bf8L, 0x6003604dL, 0xd1fd8346L, 0xf6381fb0L, 0x7745ae04L, 0xd736fcccL,
              0x83426b33L, 0xf01eab71L, 0xb0804187L, 0x3c005e5fL, 0x77a057beL, 0xbde8ae24L,
              0x55464299L, 0xbf582e61L, 0x4e58f48fL, 0xf2ddfda2L, 0xf474ef38L, 0x8789bdc2L,
              0x5366f9c3L, 0xc8b38e74L, 0xb475f255L, 0x46fcd9b9L, 0x7aeb2661L, 0x8b1ddf84L,
              0x846a0e79L, 0x915f95e2L, 0x466e598eL, 0x20b45770L, 0x8cd55591L, 0xc902de4cL,
              0xb90bace1L, 0xbb8205d0L, 0x11a86248L, 0x7574a99eL, 0xb77f19b6L, 0xe0a9dc09L,
              0x662d09a1L, 0xc4324633L, 0xe85a1f02L, 0x09f0be8cL, 0x4a99a025L, 0x1d6efe10L,
              0x1ab93d1dL, 0x0ba5a4dfL, 0xa186f20fL, 0x2868f169L, 0xdcb7da83L, 0x573906feL,
              0xa1e2ce9bL, 0x4fcd7f52L, 0x50115e01L, 0xa70683faL, 0xa002b5c4L, 0x0de6d027L,
              0x9af88c27L, 0x773f8641L, 0xc3604c06L, 0x61a806b5L, 0xf0177a28L, 0xc0f586e0L,
              0x006058aaL, 0x30dc7d62L, 0x11e69ed7L, 0x2338ea63L, 0x53c2dd94L, 0xc2c21634L,
              0xbbcbee56L, 0x90bcb6deL, 0xebfc7da1L, 0xce591d76L, 0x6f05e409L, 0x4b7c0188L,
              0x39720a3dL, 0x7c927c24L, 0x86e3725fL, 0x724d9db9L, 0x1ac15bb4L, 0xd39eb8fcL,
              0xed545578L, 0x08fca5b5L, 0xd83d7cd3L, 0x4dad0fc4L, 0x1e50ef5eL, 0xb161e6f8L,
              0xa28514d9L, 0x6c51133cL, 0x6fd5c7e7L, 0x56e14ec4L, 0x362abfceL, 0xddc6c837L,
              0xd79a3234L, 0x92638212L, 0x670efa8eL, 0x406000e0L
            },

            {
              0x3a39ce37L, 0xd3faf5cfL, 0xabc27737L, 0x5ac52d1bL, 0x5cb0679eL, 0x4fa33742L,
              0xd3822740L, 0x99bc9bbeL, 0xd5118e9dL, 0xbf0f7315L, 0xd62d1c7eL, 0xc700c47bL,
              0xb78c1b6bL, 0x21a19045L, 0xb26eb1beL, 0x6a366eb4L, 0x5748ab2fL, 0xbc946e79L,
              0xc6a376d2L, 0x6549c2c8L, 0x530ff8eeL, 0x468dde7dL, 0xd5730a1dL, 0x4cd04dc6L,
              0x2939bbdbL, 0xa9ba4650L, 0xac9526e8L, 0xbe5ee304L, 0xa1fad5f0L, 0x6a2d519aL,
              0x63ef8ce2L, 0x9a86ee22L, 0xc089c2b8L, 0x43242ef6L, 0xa51e03aaL, 0x9cf2d0a4L,
              0x83c061baL, 0x9be96a4dL, 0x8fe51550L, 0xba645bd6L, 0x2826a2f9L, 0xa73a3ae1L,
              0x4ba99586L, 0xef5562e9L, 0xc72fefd3L, 0xf752f7daL, 0x3f046f69L, 0x77fa0a59L,
              0x80e4a915L, 0x87b08601L, 0x9b09e6adL, 0x3b3ee593L, 0xe990fd5aL, 0x9e34d797L,
              0x2cf0b7d9L, 0x022b8b51L, 0x96d5ac3aL, 0x017da67dL, 0xd1cf3ed6L, 0x7c7d2d28L,
              0x1f9f25cfL, 0xadf2b89bL, 0x5ad6b472L, 0x5a88f54cL, 0xe029ac71L, 0xe019a5e6L,
              0x47b0acfdL, 0xed93fa9bL, 0xe8d3c48dL, 0x283b57ccL, 0xf8d56629L, 0x79132e28L,
              0x785f0191L, 0xed756055L, 0xf7960e44L, 0xe3d35e8cL, 0x15056dd4L, 0x88f46dbaL,
              0x03a16125L, 0x0564f0bdL, 0xc3eb9e15L, 0x3c9057a2L, 0x97271aecL, 0xa93a072aL,
              0x1b3f6d9bL, 0x1e6321f5L, 0xf59c66fbL, 0x26dcf319L, 0x7533d928L, 0xb155fdf5L,
              0x03563482L, 0x8aba3cbbL, 0x28517711L, 0xc20ad9f8L, 0xabcc5167L, 0xccad925fL,
              0x4de81751L, 0x3830dc8eL, 0x379d5862L, 0x9320f991L, 0xea7a90c2L, 0xfb3e7bceL,
              0x5121ce64L, 0x774fbe32L, 0xa8b6e37eL, 0xc3293d46L, 0x48de5369L, 0x6413e680L,
              0xa2ae0810L, 0xdd6db224L, 0x69852dfdL, 0x09072166L, 0xb39a460aL, 0x6445c0ddL,
              0x586cdecfL, 0x1c20c8aeL, 0x5bbef7ddL, 0x1b588d40L, 0xccd2017fL, 0x6bb4e3bbL,
              0xdda26a7eL, 0x3a59ff45L, 0x3e350a44L, 0xbcb4cdd5L, 0x72eacea8L, 0xfa6484bbL,
              0x8d6612aeL, 0xbf3c6f47L, 0xd29be463L, 0x542f5d9eL, 0xaec2771bL, 0xf64e6370L,
              0x740e0d8dL, 0xe75b1357L, 0xf8721671L, 0xaf537d5dL, 0x4040cb08L, 0x4eb4e2ccL,
              0x34d2466aL, 0x0115af84L, 0xe1b00428L, 0x95983a1dL, 0x06b89fb4L, 0xce6ea048L,
              0x6f3f3b82L, 0x3520ab82L, 0x011a1d4bL, 0x277227f8L, 0x611560b1L, 0xe7933fdcL,
              0xbb3a792bL, 0x344525bdL, 0xa08839e1L, 0x51ce794bL, 0x2f32c9b7L, 0xa01fbac9L,
              0xe01cc87eL, 0xbcc7d1f6L, 0xcf0111c3L, 0xa1e8aac7L, 0x1a908749L, 0xd44fbd9aL,
              0xd0dadecbL, 0xd50ada38L, 0x0339c32aL, 0xc6913667L, 0x8df9317cL, 0xe0b12b4fL,
              0xf79e59b7L, 0x43f5bb3aL, 0xf2d519ffL, 0x27d9459cL, 0xbf97222cL, 0x15e6fc2aL,
              0x0f91fc71L, 0x9b941525L, 0xfae59361L, 0xceb69cebL, 0xc2a86459L, 0x12baa8d1L,
              0xb6c1075eL, 0xe3056a0cL, 0x10d25065L, 0xcb03a442L, 0xe0ec6e0eL, 0x1698db3bL,
              0x4c98a0beL, 0x3278e964L, 0x9f1f9532L, 0xe0d392dfL, 0xd3a0342bL, 0x8971f21eL,
              0x1b0a7441L, 0x4ba3348cL, 0xc5be7120L, 0xc37632d8L, 0xdf359f8dL, 0x9b992f2eL,
              0xe60b6f47L, 0x0fe3f11dL, 0xe54cda54L, 0x1edad891L, 0xce6279cfL, 0xcd3e7e6fL,
              0x1618b166L, 0xfd2c1d05L, 0x848fd2c5L, 0xf6fb2299L, 0xf523f357L, 0xa6327623L,
              0x93a83531L, 0x56cccd02L, 0xacf08162L, 0x5a75ebb5L, 0x6e163697L, 0x88d273ccL,
              0xde966292L, 0x81b949d0L, 0x4c50901bL, 0x71c65614L, 0xe6c6c7bdL, 0x327a140aL,
              0x45e1d006L, 0xc3f27b9aL, 0xc9aa53fdL, 0x62a80f00L, 0xbb25bfe2L, 0x35bdd2f6L,
              0x71126905L, 0xb2040222L, 0xb6cbcf7cL, 0xcd769c2bL, 0x53113ec0L, 0x1640e3d3L,
              0x38abbd60L, 0x2547adf0L, 0xba38209cL, 0xf746ce76L, 0x77afa1c5L, 0x20756060L,
              0x85cbfe4eL, 0x8ae88dd8L, 0x7aaaf9b0L, 0x4cf9aa7eL, 0x1948c25cL, 0x02fb8a8cL,
              0x01c36ae4L, 0xd6ebe1f9L, 0x90d4f869L, 0xa65cdea0L, 0x3f09252dL, 0xc208e69fL,
              0xb74e6132L, 0xce77e25bL, 0x578fdfe3L, 0x3ac372e6L}
        };
        */
 
        /* P boxes based on PI in hexadecimal format
         * Unsigned integer of 32 bits (saved as long) derived from PI digits 
         */
        /*
         private long [] P_ORIGINAL =  {
              0x243f6a88L, 0x85a308d3L, 0x13198a2eL, 0x03707344L, 0xa4093822L, 0x299f31d0L,
              0x082efa98L, 0xec4e6c89L, 0x452821e6L, 0x38d01377L, 0xbe5466cfL, 0x34e90c6cL,
              0xc0ac29b7L, 0xc97c50ddL, 0x3f84d5b5L, 0xb5470917L, 0x9216d5d9L, 0x8979fb1bL
         };
        */
 
        /* P boxes based on PI in Decimal format
         * Unsigned integer of 32 bits (saved as long) derived from PI digits 
         */
	private final static long [] P_ORIGINAL = 
	{
	  608135816L, 2242054355L,  320440878L,   57701188L,
	 2752067618L,  698298832L,  137296536L, 3964562569L,
	 1160258022L,  953160567L, 3193202383L,  887688300L,
	 3232508343L, 3380367581L, 1065670069L, 3041331479L,
	 2450970073L, 2306472731L
	} ;

        /* S boxes based on PI in decimal format
         * Unsigned integer of 32 bits (saved as long) derived from PI digits 
         */
	private final static long [][] S_ORIGINAL = {

       { 3509652390L, 2564797868L,  805139163L, 3491422135L,
	 3101798381L, 1780907670L, 3128725573L, 4046225305L,
	  614570311L, 3012652279L,  134345442L, 2240740374L,
	 1667834072L, 1901547113L, 2757295779L, 4103290238L,
	  227898511L, 1921955416L, 1904987480L, 2182433518L,
	 2069144605L, 3260701109L, 2620446009L,  720527379L,
	 3318853667L,  677414384L, 3393288472L, 3101374703L,
	 2390351024L, 1614419982L, 1822297739L, 2954791486L,
	 3608508353L, 3174124327L, 2024746970L, 1432378464L,
	 3864339955L, 2857741204L, 1464375394L, 1676153920L,
	 1439316330L,  715854006L, 3033291828L,  289532110L,
	 2706671279L, 2087905683L, 3018724369L, 1668267050L,
	  732546397L, 1947742710L, 3462151702L, 2609353502L,
	 2950085171L, 1814351708L, 2050118529L,  680887927L,
	  999245976L, 1800124847L, 3300911131L, 1713906067L,
	 1641548236L, 4213287313L, 1216130144L, 1575780402L,
	 4018429277L, 3917837745L, 3693486850L, 3949271944L,
	  596196993L, 3549867205L,  258830323L, 2213823033L,
	  772490370L, 2760122372L, 1774776394L, 2652871518L,
	  566650946L, 4142492826L, 1728879713L, 2882767088L,
	 1783734482L, 3629395816L, 2517608232L, 2874225571L,
	 1861159788L,  326777828L, 3124490320L, 2130389656L,
	 2716951837L,  967770486L, 1724537150L, 2185432712L,
	 2364442137L, 1164943284L, 2105845187L,  998989502L,
	 3765401048L, 2244026483L, 1075463327L, 1455516326L,
	 1322494562L,  910128902L,  469688178L, 1117454909L,
	  936433444L, 3490320968L, 3675253459L, 1240580251L,
	  122909385L, 2157517691L,  634681816L, 4142456567L,
	 3825094682L, 3061402683L, 2540495037L,   79693498L,
	 3249098678L, 1084186820L, 1583128258L,  426386531L,
	 1761308591L, 1047286709L,  322548459L,  995290223L,
	 1845252383L, 2603652396L, 3431023940L, 2942221577L,
	 3202600964L, 3727903485L, 1712269319L,  422464435L,
	 3234572375L, 1170764815L, 3523960633L, 3117677531L,
	 1434042557L,  442511882L, 3600875718L, 1076654713L,
	 1738483198L, 4213154764L, 2393238008L, 3677496056L,
	 1014306527L, 4251020053L,  793779912L, 2902807211L,
	  842905082L, 4246964064L, 1395751752L, 1040244610L,
	 2656851899L, 3396308128L,  445077038L, 3742853595L,
	 3577915638L,  679411651L, 2892444358L, 2354009459L,
	 1767581616L, 3150600392L, 3791627101L, 3102740896L,
	  284835224L, 4246832056L, 1258075500L,  768725851L,
	 2589189241L, 3069724005L, 3532540348L, 1274779536L,
	 3789419226L, 2764799539L, 1660621633L, 3471099624L,
	 4011903706L,  913787905L, 3497959166L,  737222580L,
	 2514213453L, 2928710040L, 3937242737L, 1804850592L,
	 3499020752L, 2949064160L, 2386320175L, 2390070455L,
	 2415321851L, 4061277028L, 2290661394L, 2416832540L,
	 1336762016L, 1754252060L, 3520065937L, 3014181293L,
	  791618072L, 3188594551L, 3933548030L, 2332172193L,
	 3852520463L, 3043980520L,  413987798L, 3465142937L,
	 3030929376L, 4245938359L, 2093235073L, 3534596313L,
	  375366246L, 2157278981L, 2479649556L,  555357303L,
	 3870105701L, 2008414854L, 3344188149L, 4221384143L,
	 3956125452L, 2067696032L, 3594591187L, 2921233993L,
	    2428461L,  544322398L,  577241275L, 1471733935L,
	  610547355L, 4027169054L, 1432588573L, 1507829418L,
	 2025931657L, 3646575487L,  545086370L,   48609733L,
	 2200306550L, 1653985193L,  298326376L, 1316178497L,
	 3007786442L, 2064951626L,  458293330L, 2589141269L,
	 3591329599L, 3164325604L,  727753846L, 2179363840L,
	  146436021L, 1461446943L, 4069977195L,  705550613L,
	 3059967265L, 3887724982L, 4281599278L, 3313849956L,
	 1404054877L, 2845806497L,  146425753L, 1854211946L},

	{ 1266315497L, 3048417604L, 3681880366L, 3289982499L,
	 2909710000L, 1235738493L, 2632868024L, 2414719590L,
	 3970600049L, 1771706367L, 1449415276L, 3266420449L,
	  422970021L, 1963543593L, 2690192192L, 3826793022L,
	 1062508698L, 1531092325L, 1804592342L, 2583117782L,
	 2714934279L, 4024971509L, 1294809318L, 4028980673L,
	 1289560198L, 2221992742L, 1669523910L,   35572830L,
	  157838143L, 1052438473L, 1016535060L, 1802137761L,
	 1753167236L, 1386275462L, 3080475397L, 2857371447L,
	 1040679964L, 2145300060L, 2390574316L, 1461121720L,
	 2956646967L, 4031777805L, 4028374788L,   33600511L,
	 2920084762L, 1018524850L,  629373528L, 3691585981L,
	 3515945977L, 2091462646L, 2486323059L,  586499841L,
	  988145025L,  935516892L, 3367335476L, 2599673255L,
	 2839830854L,  265290510L, 3972581182L, 2759138881L,
	 3795373465L, 1005194799L,  847297441L,  406762289L,
	 1314163512L, 1332590856L, 1866599683L, 4127851711L,
	  750260880L,  613907577L, 1450815602L, 3165620655L,
	 3734664991L, 3650291728L, 3012275730L, 3704569646L,
	 1427272223L,  778793252L, 1343938022L, 2676280711L,
	 2052605720L, 1946737175L, 3164576444L, 3914038668L,
	 3967478842L, 3682934266L, 1661551462L, 3294938066L,
	 4011595847L,  840292616L, 3712170807L,  616741398L,
	  312560963L,  711312465L, 1351876610L,  322626781L,
	 1910503582L,  271666773L, 2175563734L, 1594956187L,
	   70604529L, 3617834859L, 1007753275L, 1495573769L,
	 4069517037L, 2549218298L, 2663038764L,  504708206L,
	 2263041392L, 3941167025L, 2249088522L, 1514023603L,
	 1998579484L, 1312622330L,  694541497L, 2582060303L,
	 2151582166L, 1382467621L,  776784248L, 2618340202L,
	 3323268794L, 2497899128L, 2784771155L,  503983604L,
	 4076293799L,  907881277L,  423175695L,  432175456L,
	 1378068232L, 4145222326L, 3954048622L, 3938656102L,
	 3820766613L, 2793130115L, 2977904593L,   26017576L,
	 3274890735L, 3194772133L, 1700274565L, 1756076034L,
	 4006520079L, 3677328699L,  720338349L, 1533947780L,
	  354530856L,  688349552L, 3973924725L, 1637815568L,
	  332179504L, 3949051286L,   53804574L, 2852348879L,
	 3044236432L, 1282449977L, 3583942155L, 3416972820L,
	 4006381244L, 1617046695L, 2628476075L, 3002303598L,
	 1686838959L,  431878346L, 2686675385L, 1700445008L,
	 1080580658L, 1009431731L,  832498133L, 3223435511L,
	 2605976345L, 2271191193L, 2516031870L, 1648197032L,
	 4164389018L, 2548247927L,  300782431L,  375919233L,
	  238389289L, 3353747414L, 2531188641L, 2019080857L,
	 1475708069L,  455242339L, 2609103871L,  448939670L,
	 3451063019L, 1395535956L, 2413381860L, 1841049896L,
	 1491858159L,  885456874L, 4264095073L, 4001119347L,
	 1565136089L, 3898914787L, 1108368660L,  540939232L,
	 1173283510L, 2745871338L, 3681308437L, 4207628240L,
	 3343053890L, 4016749493L, 1699691293L, 1103962373L,
	 3625875870L, 2256883143L, 3830138730L, 1031889488L,
	 3479347698L, 1535977030L, 4236805024L, 3251091107L,
	 2132092099L, 1774941330L, 1199868427L, 1452454533L,
	  157007616L, 2904115357L,  342012276L,  595725824L,
	 1480756522L,  206960106L,  497939518L,  591360097L,
	  863170706L, 2375253569L, 3596610801L, 1814182875L,
	 2094937945L, 3421402208L, 1082520231L, 3463918190L,
	 2785509508L,  435703966L, 3908032597L, 1641649973L,
	 2842273706L, 3305899714L, 1510255612L, 2148256476L,
	 2655287854L, 3276092548L, 4258621189L,  236887753L,
	 3681803219L,  274041037L, 1734335097L, 3815195456L,
	 3317970021L, 1899903192L, 1026095262L, 4050517792L,
	  356393447L, 2410691914L, 3873677099L, 3682840055L},

	{ 3913112168L, 2491498743L, 4132185628L, 2489919796L,
	 1091903735L, 1979897079L, 3170134830L, 3567386728L,
	 3557303409L,  857797738L, 1136121015L, 1342202287L,
	  507115054L, 2535736646L,  337727348L, 3213592640L,
	 1301675037L, 2528481711L, 1895095763L, 1721773893L,
	 3216771564L,   62756741L, 2142006736L,  835421444L,
	 2531993523L, 1442658625L, 3659876326L, 2882144922L,
	  676362277L, 1392781812L,  170690266L, 3921047035L,
	 1759253602L, 3611846912L, 1745797284L,  664899054L,
	 1329594018L, 3901205900L, 3045908486L, 2062866102L,
	 2865634940L, 3543621612L, 3464012697L, 1080764994L,
	  553557557L, 3656615353L, 3996768171L,  991055499L,
	  499776247L, 1265440854L,  648242737L, 3940784050L,
	  980351604L, 3713745714L, 1749149687L, 3396870395L,
	 4211799374L, 3640570775L, 1161844396L, 3125318951L,
	 1431517754L,  545492359L, 4268468663L, 3499529547L,
	 1437099964L, 2702547544L, 3433638243L, 2581715763L,
	 2787789398L, 1060185593L, 1593081372L, 2418618748L,
	 4260947970L,   69676912L, 2159744348L,   86519011L,
	 2512459080L, 3838209314L, 1220612927L, 3339683548L,
	  133810670L, 1090789135L, 1078426020L, 1569222167L,
	  845107691L, 3583754449L, 4072456591L, 1091646820L,
	  628848692L, 1613405280L, 3757631651L,  526609435L,
	  236106946L,   48312990L, 2942717905L, 3402727701L,
	 1797494240L,  859738849L,  992217954L, 4005476642L,
	 2243076622L, 3870952857L, 3732016268L,  765654824L,
	 3490871365L, 2511836413L, 1685915746L, 3888969200L,
	 1414112111L, 2273134842L, 3281911079L, 4080962846L,
	  172450625L, 2569994100L,  980381355L, 4109958455L,
	 2819808352L, 2716589560L, 2568741196L, 3681446669L,
	 3329971472L, 1835478071L,  660984891L, 3704678404L,
	 4045999559L, 3422617507L, 3040415634L, 1762651403L,
	 1719377915L, 3470491036L, 2693910283L, 3642056355L,
	 3138596744L, 1364962596L, 2073328063L, 1983633131L,
	  926494387L, 3423689081L, 2150032023L, 4096667949L,
	 1749200295L, 3328846651L,  309677260L, 2016342300L,
	 1779581495L, 3079819751L,  111262694L, 1274766160L,
	  443224088L,  298511866L, 1025883608L, 3806446537L,
	 1145181785L,  168956806L, 3641502830L, 3584813610L,
	 1689216846L, 3666258015L, 3200248200L, 1692713982L,
	 2646376535L, 4042768518L, 1618508792L, 1610833997L,
	 3523052358L, 4130873264L, 2001055236L, 3610705100L,
	 2202168115L, 4028541809L, 2961195399L, 1006657119L,
	 2006996926L, 3186142756L, 1430667929L, 3210227297L,
	 1314452623L, 4074634658L, 4101304120L, 2273951170L,
	 1399257539L, 3367210612L, 3027628629L, 1190975929L,
	 2062231137L, 2333990788L, 2221543033L, 2438960610L,
	 1181637006L,  548689776L, 2362791313L, 3372408396L,
	 3104550113L, 3145860560L,  296247880L, 1970579870L,
	 3078560182L, 3769228297L, 1714227617L, 3291629107L,
	 3898220290L,  166772364L, 1251581989L,  493813264L,
	  448347421L,  195405023L, 2709975567L,  677966185L,
	 3703036547L, 1463355134L, 2715995803L, 1338867538L,
	 1343315457L, 2802222074L, 2684532164L,  233230375L,
	 2599980071L, 2000651841L, 3277868038L, 1638401717L,
	 4028070440L, 3237316320L,    6314154L,  819756386L,
	  300326615L,  590932579L, 1405279636L, 3267499572L,
	 3150704214L, 2428286686L, 3959192993L, 3461946742L,
	 1862657033L, 1266418056L,  963775037L, 2089974820L,
	 2263052895L, 1917689273L,  448879540L, 3550394620L,
	 3981727096L,  150775221L, 3627908307L, 1303187396L,
	  508620638L, 2975983352L, 2726630617L, 1817252668L,
	 1876281319L, 1457606340L,  908771278L, 3720792119L,
	 3617206836L, 2455994898L, 1729034894L, 1080033504L},

	{  976866871L, 3556439503L, 2881648439L, 1522871579L,
	 1555064734L, 1336096578L, 3548522304L, 2579274686L,
	 3574697629L, 3205460757L, 3593280638L, 3338716283L,
	 3079412587L,  564236357L, 2993598910L, 1781952180L,
	 1464380207L, 3163844217L, 3332601554L, 1699332808L,
	 1393555694L, 1183702653L, 3581086237L, 1288719814L,
	  691649499L, 2847557200L, 2895455976L, 3193889540L,
	 2717570544L, 1781354906L, 1676643554L, 2592534050L,
	 3230253752L, 1126444790L, 2770207658L, 2633158820L,
	 2210423226L, 2615765581L, 2414155088L, 3127139286L,
	  673620729L, 2805611233L, 1269405062L, 4015350505L,
	 3341807571L, 4149409754L, 1057255273L, 2012875353L,
	 2162469141L, 2276492801L, 2601117357L,  993977747L,
	 3918593370L, 2654263191L,  753973209L,   36408145L,
	 2530585658L,   25011837L, 3520020182L, 2088578344L,
	  530523599L, 2918365339L, 1524020338L, 1518925132L,
	 3760827505L, 3759777254L, 1202760957L, 3985898139L,
	 3906192525L,  674977740L, 4174734889L, 2031300136L,
	 2019492241L, 3983892565L, 4153806404L, 3822280332L,
	  352677332L, 2297720250L,   60907813L,   90501309L,
	 3286998549L, 1016092578L, 2535922412L, 2839152426L,
	  457141659L,  509813237L, 4120667899L,  652014361L,
	 1966332200L, 2975202805L,   55981186L, 2327461051L,
	  676427537L, 3255491064L, 2882294119L, 3433927263L,
	 1307055953L,  942726286L,  933058658L, 2468411793L,
	 3933900994L, 4215176142L, 1361170020L, 2001714738L,
	 2830558078L, 3274259782L, 1222529897L, 1679025792L,
	 2729314320L, 3714953764L, 1770335741L,  151462246L,
	 3013232138L, 1682292957L, 1483529935L,  471910574L,
	 1539241949L,  458788160L, 3436315007L, 1807016891L,
	 3718408830L,  978976581L, 1043663428L, 3165965781L,
	 1927990952L, 4200891579L, 2372276910L, 3208408903L,
	 3533431907L, 1412390302L, 2931980059L, 4132332400L,
	 1947078029L, 3881505623L, 4168226417L, 2941484381L,
	 1077988104L, 1320477388L,  886195818L,   18198404L,
	 3786409000L, 2509781533L,  112762804L, 3463356488L,
	 1866414978L,  891333506L,   18488651L,  661792760L,
	 1628790961L, 3885187036L, 3141171499L,  876946877L,
	 2693282273L, 1372485963L,  791857591L, 2686433993L,
	 3759982718L, 3167212022L, 3472953795L, 2716379847L,
	  445679433L, 3561995674L, 3504004811L, 3574258232L,
	   54117162L, 3331405415L, 2381918588L, 3769707343L,
	 4154350007L, 1140177722L, 4074052095L,  668550556L,
	 3214352940L,  367459370L,  261225585L, 2610173221L,
	 4209349473L, 3468074219L, 3265815641L,  314222801L,
	 3066103646L, 3808782860L,  282218597L, 3406013506L,
	 3773591054L,  379116347L, 1285071038L,  846784868L,
	 2669647154L, 3771962079L, 3550491691L, 2305946142L,
	  453669953L, 1268987020L, 3317592352L, 3279303384L,
	 3744833421L, 2610507566L, 3859509063L,  266596637L,
	 3847019092L,  517658769L, 3462560207L, 3443424879L,
	  370717030L, 4247526661L, 2224018117L, 4143653529L,
	 4112773975L, 2788324899L, 2477274417L, 1456262402L,
	 2901442914L, 1517677493L, 1846949527L, 2295493580L,
	 3734397586L, 2176403920L, 1280348187L, 1908823572L,
	 3871786941L,  846861322L, 1172426758L, 3287448474L,
	 3383383037L, 1655181056L, 3139813346L,  901632758L,
	 1897031941L, 2986607138L, 3066810236L, 3447102507L,
	 1393639104L,  373351379L,  950779232L,  625454576L,
	 3124240540L, 4148612726L, 2007998917L,  544563296L,
	 2244738638L, 2330496472L, 2058025392L, 1291430526L,
	  424198748L,   50039436L,   29584100L, 3605783033L,
	 2429876329L, 2791104160L, 1057563949L, 3255363231L,
	 3075367218L, 3463963227L, 1469046755L,  985887462L}
	};

	/* Pad the plain text making its length multiple of 8 bytes (64 bits).
         * The plain text length must be multiple of 8 bytes because the blowfish
         * encryption algorithm process blocks of 64 bits of raw data each time. 
         * Here is how we do it:
	 *   - Determine how many chars must be added to complete 8 bytes (64 bits)
         *     using the formula "8 - len % mod 8".
         *   - Add n times the value n to the end of the plain text.
         *   - The posible values of n are 0x01, ..., 0x08.
         *   - If n = 8 then you must add 8 times the value 0x08.
         * Based on recommendations from http://www.di-mgt.com.au/cryptopad.html
         * @params data Raw data that will be encrypted after padding
         */ 
	private byte[] pad(byte [] data){
		int dataLen = data.length;		
		int padding = 8 - (dataLen % 8);
		byte[] padded = new byte[dataLen + padding];
		for(int i=0;i<dataLen;i++){
		   padded[i]=data[i];
		}
       	        for(int i=0;i<padding;i++){
		   padded[dataLen+padding-1-i] = (byte) (PADDING_BYTES[padding] & 0xff);
		}
		return padded;
	}

	/* Delete pad from the plain text that makes its length mutiple of 8 bytes (64 bits)
         * Based on recommendations from http://www.di-mgt.com.au/cryptopad.html
         * @params data Raw data that will be encrypted after padding
         */ 
	private byte[] unpad(byte [] data) throws BlowfishException{
		int dataLen = data.length;		
		int padding = PADDING_BYTES[data[dataLen-1]];
		boolean isOkPadding = true;
		for(int i=0;i<padding && isOkPadding;i++){
		   isOkPadding = isOkPadding && (data[dataLen-1-i]==padding);
		}
		byte [] unpadded; 
		if (isOkPadding){
			unpadded = new byte[dataLen-padding];
			System.arraycopy(data, 0, unpadded, 0, dataLen-padding);
		}else{
			throw new BlowfishException("Data has a wrong padding.");
		}
		return unpadded;
	}
	
	public byte[] crypt(final byte [] rawData, final boolean encrypt) throws BlowfishException{
		
		//Cloning rawData allow byte modifications
		int rawDataLen = rawData.length;
	        byte [] data = new byte[rawDataLen];
		System.arraycopy(rawData, 0, data, 0, rawDataLen);
		
		//On encryption we must pad
		data = encrypt ? pad(data) : data;
		
		//Ciphering
		int dataLen = data.length;
		long block;
		for(int i=0;i<dataLen;i=i+8){
                    block = (((long) data[i+0] & 0xff) << 56) | 
                            (((long) data[i+1] & 0xff) << 48) |
                            (((long) data[i+2] & 0xff) << 40) | 
                            (((long) data[i+3] & 0xff) << 32) |
 			    (((long) data[i+4] & 0xff) << 24) | 
                            (((long) data[i+5] & 0xff) << 16) |
                            (((long) data[i+6] & 0xff) << 8) | 
                            (((long) data[i+7] & 0xff));
		    if (encrypt){
		    	block = encrypt(block);
		    }else{
			block = decrypt(block);
		    }
		    data[i]   = (byte) ((block >>> 56) & 0xff);
		    data[i+1] = (byte) ((block >>> 48) & 0xff);
		    data[i+2] = (byte) ((block >>> 40) & 0xff);
		    data[i+3] = (byte) ((block >>> 32) & 0xff);
		    data[i+4] = (byte) ((block >>> 24) & 0xff);
		    data[i+5] = (byte) ((block >>> 16) & 0xff);
		    data[i+6] = (byte) ((block >>>  8) & 0xff);
		    data[i+7] = (byte) ((block >>>  0) & 0xff);
		}
		
		//On decryption we must unpad befor return
		return encrypt ? data : unpad(data);		
	}

        /* Initialize the round P(s) and S box(es) values XORing them with the passed key string,
         * changing the state of the cipher from UNITIALIZED to INITIALIZING and then INITIALIZED.
         * 
         * @param key A string key from 4 to 56 bytes (32-448 bits), recomended 128 bits
         * @throws BlowfishException
         */
	public void initialize(byte [] key) throws BlowfishException{
	   int keyLen = key.length;

	   if (keyLen<4 || keyLen>56 || (keyLen % 4 != 0)){ //Up to 448 bits (P1 ... P14 each of 32 bits / 4 bytes)
		throw new BlowfishException("Wrong key size s=" + keyLen + " expected 4 >= s <= 56 bytes and divided exactly by 4");
	   } 

	   state = INITIALIZING;

           long keyPart;
	   int j = 0;
	   // XOR P1 .. P14 with 32 bits parts of the key
	   for(int i=0;i<18;i++){
		if (j==keyLen) j = 0;
		keyPart = (
                           (((long) key[j+0] & 0xff) << 24) | 
                           (((long) key[j+1] & 0xff) << 16) |
                           (((long) key[j+2] & 0xff) << 8) | 
                           (((long) key[j+3] & 0xff))
                          ); //OHO 
		j=j+4;
		P[i] = (P[i] ^ keyPart);
	   }

	   //Prepare the keys (encrypt P[*])
           long T = 0;
	   for (int i = 0; i<18; i=i+2){
		T = encrypt(T);
                P[i] = T >>> 32;
		P[i+1] = ((T << 32) >>> 32);
            }

	    //Prepare the sboxes (encrypt S[*][*]
            for (int k = 0; k < 4; k++){
		    for (int i = 0; i<256; i=i+2){
			T = encrypt(T);
			S[k][i] = T >>> 32;
			S[k][i+1] = ((T << 32) >>> 32);
		    }
	    }
	    
	    state = INITIALIZED;
        }

	/* This is F(x) function implementation of blowfish algorithm
         * @param x A long primitive type (unsigned)
	 * @return 64 bits of encrypted data
         */
	private long f(long x){		
		int a = (int) ((x >>> 24) & 0xff);	
		int b = (int) ((x >>> 16) & 0xff);		
		int c = (int) ((x >>> 8) & 0xff);		
		int d = (int) (x & 0xff);
		return (((((S[0][a] + S[1][b]) % POW2TO32) ^ S[2][c]) + S[3][d]) % POW2TO32); // & 0xffffffff (Not needed)
	}

	/* Encrypt a long (64 bits, maybe signed) of raw data
         * @param x 64 bits of plain text data
	 * @return 64 bits of encrypted data
         */
	private long encrypt(long x) throws BlowfishException{
	    long xL; //"Unsigned" long
	    long xR; //"Unsigned" long
	    long xLSaved; //"Unsigned" long
	    if (state != UNINITIALIZED){
		xL = (x >>> 32);
		xR = ((x << 32) >>> 32); //& 0xffffffff doesn't work if it's signed long;
                
		for (int i = 0; i < 16; i++){
			//Xoring
			xL = xL ^ P[i]; //Not signed operands
			xR = f(xL) ^ xR; //Not signed operands
			//Swapping
			xLSaved = xL;
			xL = xR;
			xR = xLSaved;
		}

		//Undo last swaping 
		xLSaved = xL;
		xL = xR;
		xR = xLSaved;

		xR = xR ^ P[16]; //Not signed operands
		xL = xL ^ P[17]; //Not signed operands

		return (xL << 32) | (xR & 0xffffffff); //Not signed operands and return value

	    }else{

		throw new BlowfishException("Encryption key has not been initialized");

	    }
	}

	/* Decrypt a long (64 bits, maybe signed) of encrypted data
         * @param x 64 bits of encrypted data
	 * @return 64 bits of unencrypted data
         */
	private long decrypt(long x) throws BlowfishException{

	    long xL; //"Unsigned" long
	    long xR; //"Unsigned" long
	    long xLSaved; //"Unsigned" long

	    if (state != UNINITIALIZED){
		//xL and xR must be unsigned
                xL = (x >>> 32);
		xR = ((x << 32) >>> 32); //& 0xffffffff doesn't work if it's a signed long

		for (int i = 17; i > 1; i--){
			//Xoring
			xL = xL ^ P[i]; //Not signed operands
			xR = f(xL) ^ xR; //Not signed operands
			//Swapping 
			xLSaved = xL;
			xL = xR;
			xR = xLSaved;
		}

		//Undo last swapping 
		xLSaved = xL;
		xL = xR;
		xR = xLSaved;
		
		xR = xR ^ P[1]; //Not signed operands
		xL = xL ^ P[0]; //Not signed operands
		
		return (xL << 32) | (xR & 0xffffffff); //Not signed operands and return value

	    }else{

		throw new BlowfishException("Encryption key has not been initialized");

	    }

	}

	/* Decrypt a long (64 bits, maybe signed) of encrypted data
         * @param x 64 bits of encrypted data
	 * @return 64 bits of unencrypted data
         */
	private long decrypt2(long x) throws BlowfishException{

	    long xL; //"Unsigned" long
	    long xR; //"Unsigned" long
	    long xLSaved; //"Unsigned" long

	    if (state != UNINITIALIZED){
		//xL and xR must be unsigned
                xL = (x >>> 32);
		xR = ((x << 32) >>> 32); //& 0xffffffff doesn't work if it's a signed long

		//Undo last swaping 
		xLSaved = xL;
		xL = xR;
		xR = xLSaved;

		xR = xR ^ P[17]; //Not signed operands
		xL = xL ^ P[16]; //Not signed operands

		for (int i = 15; i >=0; i--){
			//Swapping 
			xLSaved = xL;
			xL = xR;
			xR = xLSaved;
			//Xoring
			xR = f(xL) ^ xR; //Not signed operands
			xL = xL ^ P[i]; //Not signed operands
		}
		return (xL << 32) | (xR & 0xffffffff); //Not signed operands and return value

	    }else{

		throw new BlowfishException("Encryption key has not been initialized");

	    }

	}

        public static final String getHexString(byte[] b) throws Exception {
                String hexString = "";
                for (int i=0; i < b.length; i++)
                        hexString += Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring(1).toUpperCase();
                return hexString;
        }


}
