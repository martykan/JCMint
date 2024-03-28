package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.ISO7816;
import jcmint.Consts;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

public class ProtocolManager {
    public final CardManager cm;

    private final static ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    public final static ECPoint G = ecSpec.getG();
    private final static Random rnd = new Random();
    private byte card_idx;

    public ProtocolManager(CardManager cm, byte card_idx) {
        this.cm = cm;
        this.card_idx = card_idx;
    }

    public ECPoint setup(BigInteger[] secrets) throws Exception {
        ECPoint[] points = new ECPoint[secrets.length];
        for (int i = 0; i < secrets.length; ++i) {
            secrets[i] = randomBigInt(32);
            points[i] = ecSpec.getG().multiply(secrets[i]);
        }
        ECPoint mintKey = points[0];
        for (int i = 1; i < secrets.length; ++i) {
            mintKey = mintKey.add(points[i]);
        }
        byte[] data = encodeBigInteger(secrets[card_idx]);
        for (int i = 0; i < secrets.length; ++i) {
            data = Util.concat(data, points[i].getEncoded(false));
        }

        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_SETUP,
                card_idx,
                (byte) secrets.length,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        Assertions.assertArrayEquals(mintKey.getEncoded(false), responseAPDU.getData());
        return mintKey;
    }

    public ECPoint hashToCurve(byte[] input) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_HASH_TO_CURVE,
                (byte) 0,
                (byte) 0,
                input
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }

    public ECPoint issue(ECPoint challenge) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_ISSUE,
                (byte) 0,
                (byte) 0,
                challenge.getEncoded(false)
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }

    public byte[] verify(byte[] message, ECPoint token, ECPoint precomputed) throws Exception {
        byte[] data = Util.concat(message, token.getEncoded(false));
        if (precomputed != null) {
            data = Util.concat(data, precomputed.getEncoded(false));
        }
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_VERIFY,
                (byte) (precomputed == null ? 0 : 1),
                (byte) 0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return responseAPDU.getData();
    }

    public ECPoint swap(byte[] message, ECPoint token, ECPoint challenge, byte[] proofs) throws Exception {
        byte[] data = Util.concat(message, token.getEncoded(false), challenge.getEncoded(false));
        data = Util.concat(data, proofs);
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_SWAP,
                (byte) 0,
                (byte) 0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }


    public boolean redeem(byte[] message, ECPoint token, byte[] proofs) throws Exception {
        byte[] data = Util.concat(message, token.getEncoded(false), proofs);
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_REDEEM,
                (byte) 0,
                (byte) 0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        Assertions.assertArrayEquals(new byte[0], responseAPDU.getData());
        return true;
    }

    public ECPoint swapSingle(byte[] message, ECPoint token, ECPoint challenge, ECPoint precomputed) throws Exception {
        byte[] data = Util.concat(message, token.getEncoded(false), challenge.getEncoded(false));
        if (precomputed != null) {
            data = Util.concat(data, precomputed.getEncoded(false));
        }

        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_SWAP_SINGLE,
                (byte) (precomputed == null ? 0 : 1),
                (byte) 0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }

    public boolean redeemSingle(byte[] message, ECPoint token, ECPoint precomputed) throws Exception {
        byte[] data = Util.concat(message, token.getEncoded(false));
        if (precomputed != null) {
            data = Util.concat(data, precomputed.getEncoded(false));
        }

        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_REDEEM_SINGLE,
                (byte) (precomputed == null ? 0 : 1),
                (byte) 0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        Assertions.assertArrayEquals(new byte[0], responseAPDU.getData());
        return true;
    }

    public static byte[] computeProof(BigInteger secret, ECPoint hashedPoint) throws Exception {
        ECPoint verifyingPoint = hashedPoint.multiply(secret);

        BigInteger r = randomBigInt(32);

        ECPoint A = hashedPoint.multiply(r);
        ECPoint B = ecSpec.getG().multiply(r);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(hashedPoint.getEncoded(false));
        md.update(verifyingPoint.getEncoded(false));
        md.update(ecSpec.getG().getEncoded(false));
        md.update(ecSpec.getG().multiply(secret).getEncoded(false));
        md.update(A.getEncoded(false));
        md.update(B.getEncoded(false));

        BigInteger e = new BigInteger(1, md.digest());
        BigInteger s = e.multiply(secret).add(r).mod(ecSpec.getN());
        byte[] proof = Util.concat(verifyingPoint.getEncoded(false), encodeBigInteger(e), encodeBigInteger(s));

        Assertions.assertTrue(verifyProof(hashedPoint, ecSpec.getG().multiply(secret), proof));
        return proof;
    }

    public static boolean verifyProof(ECPoint hashedPoint, ECPoint partialMintKey, byte[] proof) throws Exception {
        ECPoint verifyingPoint = ecSpec.getCurve().decodePoint(Arrays.copyOfRange(proof, 0, 65));
        BigInteger e = new BigInteger(1, Arrays.copyOfRange(proof, 65, 65 + 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(proof, 65 + 32, 65 + 32 + 32));

        ECPoint A = hashedPoint.multiply(s).subtract(verifyingPoint.multiply(e));
        ECPoint B = ecSpec.getG().multiply(s).subtract(partialMintKey.multiply(e));

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(hashedPoint.getEncoded(false));
        md.update(verifyingPoint.getEncoded(false));
        md.update(ecSpec.getG().getEncoded(false));
        md.update(partialMintKey.getEncoded(false));
        md.update(A.getEncoded(false));
        md.update(B.getEncoded(false));
        BigInteger result = new BigInteger(1, md.digest());
        return e.equals(result);
    }

    public static ECPoint h2c(byte[] input) throws Exception {
        return h2c(input, false);
    }

    public static ECPoint h2c(byte[] input, boolean precomputable) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Consts.H2C_DOMAIN_SEPARATOR);
        md.update(input);
        byte[] prefix = md.digest();
        byte[] counter = new byte[4];

        for (short i = 0; i < (short) 256; ++i) { // TODO consider increasing max number of iters
            md.reset();
            md.update(prefix);
            counter[0] = (byte) (i & 0xff);
            md.update(counter);
            byte[] x = md.digest();
            try {
                return ecSpec.getCurve().decodePoint(Util.concat(new byte[]{0x02}, x));
            } catch (IllegalArgumentException e) {
                if (precomputable) {
                    throw e;
                }
            }
        }
        return G;
    }

    public static BigInteger randomBigInt(int bytes) {
        return new BigInteger(bytes * 8, rnd);
    }

    public static byte[] encodeBigInteger(BigInteger x) {
        byte[] encoded = Util.trimLeadingZeroes(x.toByteArray());
        assert encoded.length <= 32;
        while (encoded.length != 32) {
            encoded = Util.concat(new byte[1], encoded);
        }
        return encoded;
    }

    public static byte[] randomMessage(boolean precomputable) {
        byte[] message;
        boolean found = false;
        do {
            message = encodeBigInteger(randomBigInt(32));
            try {
                h2c(message, precomputable);
                found = true;
            } catch (Exception ignored) {}
        } while (!found);

        return message;
    }
}
