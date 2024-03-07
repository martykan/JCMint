package jcmint;

import javacard.framework.Util;

public class Ledger {
    private final byte[] tokens = new byte[32 * 100];
    short last = 0;

    public void append(byte[] data, short offset) {
        Util.arrayCopyNonAtomic(data, offset, tokens, (short) (last++ * 32), (short) 32);
    }

    public boolean contains(byte[] data, short offset) {
        for (short i = 0; i < last; ++i) {
            if (Util.arrayCompare(data, offset, tokens, (short) (i * 32), (short) 32) == 0)
                return true;
        }
        return false;
    }

    public void reset() {
        last = 0;
    }
}
