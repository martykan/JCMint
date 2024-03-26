package jcmint;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import jcmint.jcmathlib.*;

public class Denomination {
    public final BigNat secret;
    public final byte[] partialKeys;

    public Denomination(ResourceManager rm) {
        secret = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        partialKeys = new byte[65 * Consts.MAX_PARTIES];
    }

    public void setup(short parties, byte[] secret, short secretOffset, byte[] partialKeys, short partialKeysOffset) {
        this.secret.fromByteArray(secret, secretOffset, (short) 32);
        Util.arrayCopyNonAtomic(partialKeys, partialKeysOffset, this.partialKeys, (short) 0, (short) (65 * parties));
    }
}
