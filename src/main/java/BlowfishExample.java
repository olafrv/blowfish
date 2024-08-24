/*  
 *   This file is part of Blowfish.
 *
 *   Copyright (C) Dec 23th, 2009 - Olaf Reitmaier Veracierta <olafrv@gmail.com>
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

import Blowfish.*;
import java.util.HexFormat;

public class BlowfishExample{
	/*
	 * Tests:
	 * key                     message                 encrypted (without padding) 
	 * 0123456789ABCDEF        1111111111111111        61F9C3802281B096
	 * 018310DC409B26D6        1D9D5C5018F728C2        D1ABB290658BC778
	 * More formal test data can be found at: 
	 * - http://www.schneier.com/code/vectors.txt
	 * - https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
	 * - In this source code at: src/test/java/blowfish-vectors.txt
	 *
	 * Example:
	 * key                      message                encrypted (without padding)
	 * 0000000000000000        This is a test !!!      D03A88D68530DF48C9542821F4A7C3325244
	*/
	public static void main(String args[]) throws Exception{
		byte [][] messages = {
			{ 
				(byte)0x11,(byte)0x11,
				(byte)0x11,(byte)0x11,
				(byte)0x11,(byte)0x11,
				(byte)0x11,(byte)0x11
			},
			{
				(byte)0x1D,(byte)0x9D,
				(byte)0x5C,(byte)0x50,
				(byte)0x18,(byte)0xF7,
				(byte)0x28,(byte)0xC2
			},
			"This is a test !!!".getBytes(),
		};	

		byte [][] keys = {
			{
				(byte)0x01, (byte)0x23,
				(byte)0x45, (byte)0x67,
				(byte)0x89, (byte)0xAB,
				(byte)0xCD, (byte)0xEF    
			},
			{
				(byte) 0x01, (byte) 0x83,
				(byte) 0x10, (byte) 0xDC,
				(byte) 0x40, (byte) 0x9B,
				(byte) 0x26, (byte) 0xD6
			},
			new byte[8]
		};

		String [] hexEncryptedChecks = {
			"61F9C3802281B096FD4590C8E4BB88CC",
			"D1ABB290658BC778EBDB30A09313234C",
			"D03A88D68530DF48C9542821F4A7C3325244EC722E74954A"
		};

		Blowfish bf = new Blowfish();
		String hexEncrypted;
		System.out.println("\n--- Blowfish1 ---");
		for(int i=0;i<messages.length;i++){
			bf.initialize(keys[i]);	
			System.out.println("Message Text ..... ("+messages[i].length+" bytes): '" + new String(messages[i]) + "'");
			System.out.println("Message Hex ...... ("+messages[i].length+" bytes): '" + Blowfish.getHexString(messages[i]) + "'");
			System.out.println("Key .............. ("+keys[i].length+" bytes): '" + Blowfish.getHexString(keys[i]) + "'");
			byte [] encrypted = bf.crypt(messages[i], true);	
			hexEncrypted = Blowfish2.getHexString(encrypted);
			System.out.println("Enc Hex ---------- ("+encrypted.length+" bytes): '" + hexEncrypted + "'");
			System.out.println("Enc Hex Exp ...... ("+encrypted.length+" bytes): '" + hexEncrypted + "'");
			System.out.println("Enc Hex Match .... (" + (hexEncrypted.equals(hexEncryptedChecks[i])) + ")");
			byte [] decrypted = bf.crypt(encrypted,false);
			System.out.println("Decrypted Text ... ("+decrypted.length+" bytes): '" + new String(decrypted) + "'");
			System.out.println("Decrypted Hex .... ("+decrypted.length+" bytes): '" + Blowfish.getHexString(decrypted) + "'\n");
			bf.reset();
		}
		System.out.println("Remember that before encryption message is padded to 8 multiple.");

	}
	
}
