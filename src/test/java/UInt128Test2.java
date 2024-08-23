// https://junit.org/junit5/docs/current/user-guide/

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

import Blowfish.UInt128;

public class UInt128Test2 {

    // Utility method to create UInt128 with specific hex values
    private static UInt128 fromHex(String highHex, String lowHex) {
        return new UInt128(
            Long.parseUnsignedLong(highHex, 16),
            Long.parseUnsignedLong(lowHex, 16)
        );
    }

    /* 
    @Test
    public void testAdd() {
        // Basic addition without carry
        UInt128 a = fromHex("0000000000000000", "0000000000000001");
        UInt128 b = fromHex("0000000000000000", "0000000000000001");
        UInt128 result = a.add(b);
        assertEquals(fromHex("0000000000000000", "0000000000000002"), result);

        // Addition with carry in low part
        a = fromHex("0000000000000000", "ffffffffffffffff");
        b = fromHex("0000000000000000", "0000000000000001");
        result = a.add(b);
        System.out.println(result.toHexString());
        assertEquals(fromHex("0000000000000001", "0000000000000000"), result);

        // Addition with carry in high part
        a = fromHex("0000000000000000", "0000000000000001");
        b = fromHex("0000000000000000", "0000000000000001");
        result = a.add(b);
        assertEquals(fromHex("0000000000000000", "0000000000000002"), result);

        // Maximum possible value
        a = fromHex("ffffffffffffffff", "ffffffffffffffff");
        b = fromHex("0000000000000000", "0000000000000001");
        result = a.add(b);
        assertEquals(fromHex("0000000000000000", "0000000000000000"), result);
    }
    */

    @Test
    public void testShiftLeft() {
        // Shift by 1 bit
        UInt128 a = fromHex("0000000000000000", "0000000000000001");
        UInt128 result = a.shiftLeft(1);
        assertEquals(fromHex("0000000000000000", "0000000000000002"), result);

        // Shift by 63 bits (crossing boundary)
        a = fromHex("0000000000000000", "0000000000000001");
        result = a.shiftLeft(63);
        assertEquals(fromHex("0000000000000000", "8000000000000000"), result);

        // Shift by 64 bits (high part should be non-zero)
        a = fromHex("0000000000000001", "0000000000000000");
        result = a.shiftLeft(64);
        assertEquals(fromHex("0000000000000000", "0000000000000000"), result); // no rotation

        // Shift by 128 bits (results in zero)
        a = fromHex("0000000000000001", "0000000000000000");
        result = a.shiftLeft(128);
        assertEquals(fromHex("0000000000000000", "0000000000000000"), result);
    }

    @Test
    public void testShiftRight() {
        // Shift by 1 bit
        UInt128 a = fromHex("0000000000000000", "0000000000000002");
        UInt128 result = a.shiftRight(1);
        assertEquals(fromHex("0000000000000000", "0000000000000001"), result);

        // Shift by 63 bits (crossing boundary)
        a = fromHex("0000000000000000", "8000000000000000");
        result = a.shiftRight(63);
        assertEquals(fromHex("0000000000000000", "0000000000000001"), result);

        // Shift by 64 bits (low part should be non-zero)
        a = fromHex("0000000000000000", "0000000000000001");
        result = a.shiftRight(64);
        assertEquals(fromHex("0000000000000000", "0000000000000000"), result); // no rotation

        // Shift by 128 bits (results in zero)
        a = fromHex("0000000000000001", "0000000000000000");
        result = a.shiftRight(128);
        assertEquals(fromHex("0000000000000000", "0000000000000000"), result);
    }

    @Test
    public void testAnd() {
        // Basic AND operation
        UInt128 a = fromHex("0000000000000001", "0000000000000001");
        UInt128 b = fromHex("0000000000000001", "0000000000000001");
        UInt128 result = a.and(b);
        assertEquals(fromHex("0000000000000001", "0000000000000001"), result);

        // AND operation with all zeroes
        a = fromHex("0000000000000000", "0000000000000001");
        b = fromHex("0000000000000000", "0000000000000000");
        result = a.and(b);
        assertEquals(fromHex("0000000000000000", "0000000000000000"), result);

        // AND operation with one part zero
        a = fromHex("0000000000000000", "0000000000000001");
        b = fromHex("0000000000000001", "0000000000000001");
        result = a.and(b);
        assertEquals(fromHex("0000000000000000", "0000000000000001"), result);
    }

    @Test
    public void testOr() {
        // Basic OR operation
        UInt128 a = fromHex("0000000000000001", "0000000000000001");
        UInt128 b = fromHex("0000000000000002", "0000000000000002");
        UInt128 result = a.or(b);
        assertEquals(fromHex("0000000000000003", "0000000000000003"), result);

        // OR operation with all zeroes
        a = fromHex("0000000000000000", "0000000000000001");
        b = fromHex("0000000000000000", "0000000000000000");
        result = a.or(b);
        assertEquals(fromHex("0000000000000000", "0000000000000001"), result);

        // OR operation with maximum values
        a = fromHex("ffffffffffffffff", "ffffffffffffffff");
        b = fromHex("0000000000000000", "0000000000000000");
        result = a.or(b);
        assertEquals(fromHex("ffffffffffffffff", "ffffffffffffffff"), result);
    }

    @Test
    public void testXor() {
        // Basic XOR operation
        UInt128 a = fromHex("0000000000000001", "0000000000000001");
        UInt128 b = fromHex("0000000000000002", "0000000000000002");
        UInt128 result = a.xor(b);
        assertEquals(fromHex("0000000000000003", "0000000000000003"), result);

        // XOR operation with all zeroes
        a = fromHex("0000000000000000", "0000000000000001");
        b = fromHex("0000000000000000", "0000000000000000");
        result = a.xor(b);
        assertEquals(fromHex("0000000000000000", "0000000000000001"), result);

        // XOR operation with maximum values
        a = fromHex("ffffffffffffffff", "ffffffffffffffff");
        b = fromHex("0000000000000000", "0000000000000000");
        result = a.xor(b);
        assertEquals(fromHex("ffffffffffffffff", "ffffffffffffffff"), result);
    }
}
