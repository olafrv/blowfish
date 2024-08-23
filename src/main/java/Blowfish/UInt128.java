/**
 *   UInt128.java
 *
 *   A monad-like abstraction for bitwise integer 128 bits operations.
 *
 *   Copyright (C) Aug, 2024 - Olaf Reitmaier Veracierta <olafrv@gmail.com>
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

    /* Prototype, untested!
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
