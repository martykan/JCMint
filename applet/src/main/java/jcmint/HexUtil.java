package jcmint;

import javacard.security.MessageDigest;

public class HexUtil {
    private static final byte[] HEX_CHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    public static void mdHexString(MessageDigest md, byte[] bytes, short offset, short length) {
        for (short i = 0; i < length; i++) {
            byte b = bytes[(short)(offset + i)];
            md.update(HEX_CHARS, (short) ((b >> 4) & 0x0F), (short) 1);
            md.update(HEX_CHARS, (short) (b & 0x0F), (short) 1);
        }
    }
}
