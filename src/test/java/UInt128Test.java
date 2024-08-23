import Blowfish.UInt128;

public class UInt128Test{

    public static void main(String[] args) {

        UInt128 a = new UInt128(0x0000000000000001L, 0x0000000000000000L);
        UInt128 b = new UInt128(0x0000000000000000L, 0x0000000000000001L);

        System.out.println("a: " + a);
        System.out.println("b: " + b);
        // System.out.println("a + b: " + a.add(b));
        System.out.println("a & b: " + a.and(b));
        System.out.println("a | b: " + a.or(b));
        System.out.println("a ^ b: " + a.xor(b));
        System.out.println("a << 1: " + a.shiftLeft(1));
        System.out.println("a >> 1: " + a.shiftRight(1));

        // Print binary and hex notations
        System.out.println("a (binary): " + a.toBinString());
        System.out.println("a (hex): " + a.toHexString());
        System.out.println("b (binary): " + b.toBinString());
        System.out.println("b (hex): " + b.toHexString());
    }

}