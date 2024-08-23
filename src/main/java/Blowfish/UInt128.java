package Blowfish;

public class UInt128 {
    public final long high; // left
    public final long low; // right

    public UInt128(long high, long low) {
        this.high = high;
        this.low = low;
    }

    public UInt128(long low) {
        this.high = 0;
        this.low = low;
    }

    public UInt128() {
        this.high = 0;
        this.low = 0;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        UInt128 other = (UInt128) obj;
        return high == other.high && low == other.low;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(high) ^ Long.hashCode(low);
    }

    public UInt128 shiftLeft(int n) {
        if (n == 0) return new UInt128(this.high, this.low);
        if (n >= 128) return new UInt128(0, 0);
        if (n < 64) return new UInt128(high << n | (low >>> (64 - n)), low << n);
        return new UInt128(low << (n - 64), 0);
    }

    public UInt128 shiftRight(int n) {
        if (n == 0) return new UInt128(this.high, this.low);
        if (n >= 128) return new UInt128(0, 0);
        if (n < 64) return new UInt128(high >>> n, (high << (64 - n)) | (low >>> n));
        return new UInt128(0, high >>> (n - 64));
    }

    /*
    public UInt128 add(UInt128 other) {
        long newLow = this.low + other.low;
        long carry = (newLow < this.low) ? 1 : 0;
        long newHigh = this.high + other.high + carry;
        return new UInt128(newHigh, newLow);
    } */

    public UInt128 and(UInt128 other) {
        return new UInt128(this.high & other.high, this.low & other.low);
    }

    public UInt128 or(UInt128 other) {
        return new UInt128(this.high | other.high, this.low | other.low);
    }

    public UInt128 xor(UInt128 other) {
        return new UInt128(this.high ^ other.high, this.low ^ other.low);
    }
    
    public String toBinString() {
        String highBin = Long.toBinaryString(high);
        String lowBin = Long.toBinaryString(low);
        highBin = String.format("%64s", highBin).replace(' ', '0');
        lowBin = String.format("%64s", lowBin).replace(' ', '0');
        return highBin + lowBin;
    }

    public String toHexString() {
        return String.format("%016x%016x", this.high, this.low);
    }

    @Override
    public String toString() {
        return toHexString();
    }

}
