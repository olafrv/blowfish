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

public class Blowfish2Test{
	/*
	 * Tests:
	 *   key: TESTKEYL
	 *   message: 0x00000000000000010000000000000002
	 *   encrypted: 
	 *
	 * Example:
	 *   key: 0000000000000000
	 *   message: This is a test !!!
	 *   encrypted: 
	 */
	public static void main(String args[]) throws Exception{
		byte [][] messages = {
			{ 
				(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
				(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
				(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
				(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x02,
			},
			"This is a test !!!".getBytes()
		};	

	    byte [][] keys = {
			"TESTKEY".getBytes(),
			new byte[16]
		};

		Blowfish2 bf = new Blowfish2();    
		System.out.println("\n--- Blowfish2 ---");
		for(int i=0;i<messages.length;i++){
			bf.initialize(keys[i]);	
			System.out.println("Message Text ..... ("+messages[i].length+" bytes): '" + new String(messages[i]) + "'");
			System.out.println("Message Hex ...... ("+messages[i].length+" bytes): '" + Blowfish2.getHexString(messages[i]) + "'");
			System.out.println("Key .............. ("+keys[i].length+" bytes): '" + Blowfish2.getHexString(keys[i]) + "'");
			byte [] encrypted = bf.crypt(messages[i], true);	
			System.out.println("Encrypted Hex .... ("+encrypted.length+" bytes): '" + Blowfish2.getHexString(encrypted) + "'");
			byte [] decrypted = bf.crypt(encrypted,false);
			System.out.println("Decrypted Text ... ("+decrypted.length+" bytes): '" + new String(decrypted) + "'");
			System.out.println("Decrypted Hex .... ("+decrypted.length+" bytes): '" + Blowfish2.getHexString(decrypted) + "'\n");
			bf.reset();
		}
		System.out.println("Remember that before encryption message is padded to 16 bytes multiple.");

	}
	
}
