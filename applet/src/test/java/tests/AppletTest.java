package tests;

import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.ISO7816;
import jcmint.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;

public class AppletTest extends BaseTest {
    private final byte CARD_IDX = 0;
    public AppletTest() {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(false);
    }


    @Test
    public void testSetup() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        for (int parties = 1; parties <= Consts.MAX_PARTIES; ++parties) {
            BigInteger[] secrets = new BigInteger[parties];
            pm.setup(secrets);
        }
    }

    @Test
    public void testIssue() throws Exception {
        for(int i = 1; i <= Consts.MAX_PARTIES; ++i) {
            if (CARD_IDX >= i) {
                continue;
            }
            ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
            BigInteger[] secrets = new BigInteger[i];
            pm.setup(secrets);

            BigInteger scalar = ProtocolManager.randomBigInt(32);
            ECPoint challenge = ProtocolManager.G.multiply(scalar);
            ECPoint output = pm.issue(challenge);
            Assertions.assertArrayEquals(challenge.multiply(secrets[CARD_IDX]).getEncoded(false), output.getEncoded(false));
        }
    }

    @Test
    public void testHashToCurve() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        byte[] data = new byte[32];
        Assertions.assertArrayEquals(Util.hexStringToByteArray("044cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a72532e97a708760bfdc863bc2731ce604c7b7cb9df2a55410f18ce031fc1dcfb18e"), pm.hashToCurve(data).getEncoded(false));
        data[31] = 0x01;
        Assertions.assertArrayEquals(Util.hexStringToByteArray("042e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf7b22eee931599a72e1df1628c605c47a9f282944e97f67ba52f79e2a18ac77f8"), pm.hashToCurve(data).getEncoded(false));
        data[31] = 0x02;
        Assertions.assertArrayEquals(Util.hexStringToByteArray("046cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f7231a9756caa84811bfe53cb35b626fc0faa43ccd436d07369813b55831584ac"), pm.hashToCurve(data).getEncoded(false));
    }

    @Test
    public void testUnknownInstruction() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                (byte) 0x12,
                (byte) 0x34,
                (byte) 0x56,
                new byte[0]
        );
        ResponseAPDU responseAPDU = pm.cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(responseAPDU.getSW(), ISO7816.SW_INS_NOT_SUPPORTED);
    }

    @Test
    public void testVerifyFail() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        pm.setup(new BigInteger[1]);

        pm.verify(new byte[32], ProtocolManager.G, null);
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_VERIFY,
                (byte) 0,
                (byte) 0,
                Util.concat(new byte[32], ProtocolManager.G.getEncoded(false))
        );
        ResponseAPDU responseAPDU = pm.cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(Consts.E_ALREADY_SPENT & 0xffff, responseAPDU.getSW());
    }

    @Test
    public void testVerifyProof() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        ECPoint mintKey = pm.setup(new BigInteger[1]);
        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        byte[] data = Util.concat(new byte[32], ProtocolManager.G.getEncoded(false));
        byte[] proof = pm.verify(new byte[32], ProtocolManager.G, null);

        Assertions.assertTrue(ProtocolManager.verifyProof(hashedPoint, mintKey, proof));
    }

    @Test
    public void testSwap() throws Exception {
        for (int i = 1; i < Consts.MAX_PARTIES; ++i) {
            verifySwap(false, i);
            verifySwap(true, i);
        }
    }

    public void verifySwap(boolean precomputed, int parties) throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        BigInteger[] privateKeys = new BigInteger[parties];
        pm.setup(privateKeys);
        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        ECPoint token = pm.issue(hashedPoint);
        for (int i = 0; i < parties; ++i) {
            if (i == CARD_IDX) {
                continue;
            }
            token = token.add(hashedPoint.multiply(privateKeys[i]));
        }

        byte[] proofs = new byte[0];
        for (int i = 0; i < parties; ++i) {
            if (i == CARD_IDX) {
                proofs = Util.concat(proofs, pm.verify(secret, token, precomputed ? hashedPoint : null));
            } else {
                proofs = Util.concat(proofs, ProtocolManager.computeProof(privateKeys[i], hashedPoint));
            }
        }
        // proofs = ProtocolManager.computeProof(secrets[0], hashedPoint);
        ECPoint newToken = pm.swap(secret, token, ProtocolManager.G, proofs);
        Assertions.assertArrayEquals(ProtocolManager.G.multiply(privateKeys[CARD_IDX]).getEncoded(false), newToken.getEncoded(false));
    }

    @Test
    public void testSwapSingle() throws Exception {
        swapSingle(false);
        swapSingle(true);
    }

    @Test
    public void testRedeem() throws Exception {
        verifyRedeem(false, 1);
        verifyRedeem(true, 1);
    }

    public void verifyRedeem(boolean precomputed, int parties) throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        BigInteger[] privateKeys = new BigInteger[parties];
        pm.setup(privateKeys);

        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        ECPoint token = pm.issue(hashedPoint);
        for (int i = 0; i < parties; ++i) {
            if (i == CARD_IDX) {
                continue;
            }
            token = token.add(hashedPoint.multiply(privateKeys[i]));
        }

        byte[] proofs = new byte[0];
        for (int i = 0; i < parties; ++i) {
            if (i == CARD_IDX) {
                proofs = Util.concat(proofs, pm.verify(secret, token, precomputed ? hashedPoint : null));
            } else {
                proofs = Util.concat(proofs, ProtocolManager.computeProof(privateKeys[i], hashedPoint));
            }
        }
        Assertions.assertTrue(pm.redeem(secret, token, proofs));
    }

    public void swapSingle(boolean precomputed) throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        ECPoint mintKey = pm.setup(new BigInteger[1]);

        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        ECPoint token = pm.issue(hashedPoint);

        ECPoint newToken = pm.swapSingle(secret, token, ProtocolManager.G, precomputed ? hashedPoint : null);
        Assertions.assertArrayEquals(mintKey.getEncoded(false), newToken.getEncoded(false));
    }

    @Test
    public void testRedeemSingle() throws Exception {
        redeemSingle(false);
        redeemSingle(true);
    }

    public void redeemSingle(boolean precomputed) throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        ECPoint mintKey = pm.setup(new BigInteger[1]);

        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        ECPoint token = pm.issue(hashedPoint);

        Assertions.assertTrue(pm.redeemSingle(secret, token, precomputed ? hashedPoint : null));
    }
}
