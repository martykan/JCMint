package jcmint;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import jcmint.jcmathlib.*;

public class HashToCurve {
    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    private final byte[] prefixBuffer = JCSystem.makeTransientByteArray((short) 36, JCSystem.CLEAR_ON_RESET);
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);

    public void hash(byte[] data, short offset, ECPoint output) {
        hashLong(data, offset, (short) 32, output);
    }

    public void hashLong(byte[] data, short offset, short length, ECPoint output) {
        Util.arrayFillNonAtomic(prefixBuffer, (short) 32, (short) 4, (byte) 0);
        md.reset();
        md.update(Consts.H2C_DOMAIN_SEPARATOR, (short) 0, (short) Consts.H2C_DOMAIN_SEPARATOR.length);
        md.doFinal(data, offset, length, prefixBuffer, (short) 0);

        for (short counter = 0; counter < (short) 256; ++counter) {
            md.reset();
            prefixBuffer[32] = (byte) (counter & 0xff);
            md.doFinal(prefixBuffer, (short) 0, (short) prefixBuffer.length, ramArray, (short) 0);
            if (output.fromX(ramArray, (short) 0, (short) 32))
                break;
        }
        if (!output.isYEven())
            output.negate();
    }

    public void hashPrecomputed(byte[] input, short inputOffset, byte[] result, short resultOffset, ECPoint output) {
        Util.arrayFillNonAtomic(prefixBuffer, (short) 32, (short) 4, (byte) 0);
        md.reset();
        md.update(Consts.H2C_DOMAIN_SEPARATOR, (short) 0, (short) Consts.H2C_DOMAIN_SEPARATOR.length);
        md.doFinal(input, inputOffset, (short) 32, prefixBuffer, (short) 0);

        md.reset();
        md.doFinal(prefixBuffer, (short) 0, (short) prefixBuffer.length, ramArray, (short) 0);

        if (Util.arrayCompare(ramArray, (short) 0, result, (short) (resultOffset + 1), (short) 32) != 0) {
            ISOException.throwIt(Consts.E_INVALID_PRECOMPUTE);
        }

        output.setW(result, resultOffset, (short) 65);

        if (!output.isYEven())
            output.negate();
    }
}
