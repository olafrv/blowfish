/*  
 *   This file is part of Blowfish2.
 *
 *   Copyright (C) Aug, 2024 - Olaf Reitmaier Veracierta <olafrv@gmail.com>
 *
 *   Blowfish is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Blowfish is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Blowfish.  If not, see <http://www.gnu.org/licenses/>.
 */

import Blowfish.Blowfish2;
import java.util.HexFormat;

public class Blowfish2Example{

	public static void main(String args[]) throws Exception{
		/*
		 * Examples: https://github.com/robistruck/blowfish2/blob/main/blowfish2.c
		 * key     message (hex)                    encrypted (hex without padding) 
		 * TESTKEY 00000000000000010000000000000002 7B2B9DE71D1B1C62 91C230351177BEE8
		 * A       01020304050607080910111213141516 CA38165603F9915C 61F0776A0F55E807
		 * B       01020304050607080910111213141516 D07690A78B109983 8DDF85826F2366C2
		 */

		byte [][] messages = {
			HexFormat.of().parseHex("00000000000000010000000000000002"),
			HexFormat.of().parseHex("01020304050607080910111213141516"),
			HexFormat.of().parseHex("01020304050607080910111213141516"),
			"This is a test !!!".getBytes(),
			"This is a much longer test 😊😊😊 !!!".getBytes(),
		};	

	    byte [][] keys = {
			"TESTKEY".getBytes(),
			"A".getBytes(),
			"B".getBytes(),
			new byte[16],
			"1234567812345678".getBytes(),
		};

		String [] hexEncryptedChecks = {
			"7B2B9DE71D1B1C6291C230351177BEE8DF6A89FA5A585F4275EF5156AAF05519",
			"CA38165603F9915C61F0776A0F55E8072AD9F5D255AB59B033F1E26A7E573B8E",
			"D07690A78B1099838DDF85826F2366C21C37A1FF3B0DD7B17164C3860609C5FB",
			"AF53A4C34749E843E30E847A0EAF2D180048C58FEFA58D7F5421595429C21281",
			"410529C1A9A27BDFD1638687471255FD6177EFD8BCF2DD6F83A276752532F2714B366AE942234EBBF5BA90DAEFED6B06",
		};

		Blowfish2 bf = new Blowfish2();    
		String hexEncrypted;
		System.out.println("\n--- Blowfish2 ---");
		for(int i=0;i<messages.length;i++){
			bf.initialize(keys[i]);	
			System.out.println("Message Text ..... ("+messages[i].length+" bytes): '" + new String(messages[i]) + "'");
			System.out.println("Message Hex ...... ("+messages[i].length+" bytes): '" + Blowfish2.getHexString(messages[i]) + "'");
			System.out.println("Key Hex .......... ("+keys[i].length+" bytes): '" + Blowfish2.getHexString(keys[i]) + "'");
			byte [] encrypted = bf.crypt(messages[i], true);	
			hexEncrypted = Blowfish2.getHexString(encrypted);
			System.out.println("Enc Hex ---------- ("+encrypted.length+" bytes): '" + hexEncrypted + "'");
			System.out.println("Enc Hex Exp ...... ("+encrypted.length+" bytes): '" + hexEncrypted + "'");
			System.out.println("Enc Hex Match .... (" + (hexEncrypted.equals(hexEncryptedChecks[i])) + ")");
			byte [] decrypted = bf.crypt(encrypted, false);
			System.out.println("Decrypted Text ... ("+decrypted.length+" bytes): '" + new String(decrypted) + "'");
			System.out.println("Decrypted Hex .... ("+decrypted.length+" bytes): '" + Blowfish2.getHexString(decrypted) + "'\n");
			bf.reset();
		}

		System.out.println("Remember that before encryption message is padded to 16 bytes multiple.");
	}
}
