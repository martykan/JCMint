package tests;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

import cz.muni.fi.crocs.rcard.client.Util;
import jcmint.Consts;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

public class PerformanceTest extends BaseTest {
    private final long REPEAT = 100;

    @Test
    public void measureSwapSingle() throws Exception {
        swapSingle(false);
    }

    @Test
    public void measureSwapSinglePrecomputed() throws Exception {
        swapSingle(true);
    }

    public void swapSingle(boolean precomputed) throws Exception {
        String fileName = "swap_single" + (precomputed ? "_precomputed" : "") + ".csv";
        PrintWriter file = new PrintWriter(new FileWriter(fileName, false));
        ProtocolManager pm = new ProtocolManager(connect(), (byte) 0);

        BigInteger[] privateKeys = new BigInteger[1];
        pm.setup(privateKeys);
        byte[] message = ProtocolManager.randomMessage(precomputed);
        ECPoint hashedPoint = ProtocolManager.h2c(message);
        ECPoint token = pm.issue(hashedPoint);

        for (int i = 0; i < REPEAT; ++i) {
            byte[] previousMessage = message;
            ECPoint previousHashedPoint = hashedPoint;
            message = ProtocolManager.randomMessage(precomputed);
            hashedPoint = ProtocolManager.h2c(message);
            token = pm.swapSingle(previousMessage, token, hashedPoint, precomputed ? previousHashedPoint : null);
            file.printf("%d\n", pm.cm.getLastTransmitTime());
        }
        file.close();
    }

    @Test
    public void measureVerifySwap() throws Exception {
        for (int i = 1; i <= Consts.MAX_PARTIES; ++i) {
            verifySwap(false, i);
        }
    }

    @Test
    public void measureVerifySwapPrecomputed() throws Exception {
        for (int i = 1; i <= Consts.MAX_PARTIES; ++i) {
            verifySwap(true, i);
        }
    }

    public void verifySwap(boolean precomputed, int parties) throws Exception {
        String fileName = "verify_swap_" + parties + (precomputed ? "_precomputed" : "") + ".csv";
        PrintWriter file = new PrintWriter(new FileWriter(fileName, false));
        ProtocolManager pm = new ProtocolManager(connect(), (byte) 0);

        BigInteger[] privateKeys = new BigInteger[parties];
        pm.setup(privateKeys);
        byte[] message = ProtocolManager.randomMessage(precomputed);
        ECPoint hashedPoint = ProtocolManager.h2c(message);
        ECPoint token = pm.issue(hashedPoint);

        for (int i = 1; i < privateKeys.length; ++i) {
            token = token.add(hashedPoint.multiply(privateKeys[i]));
        }

        for (int i = 0; i < REPEAT; ++i) {
            byte[] previousMessage = message;
            ECPoint previousHashedPoint = hashedPoint;
            byte[] proofs = pm.verify(previousMessage, token, precomputed ? previousHashedPoint : null);
            file.printf("%d,", pm.cm.getLastTransmitTime());
            message = ProtocolManager.randomMessage(precomputed);
            hashedPoint = ProtocolManager.h2c(message);

            for (int j = 1; j < privateKeys.length; ++j) {
                proofs = Util.concat(proofs, ProtocolManager.computeProof(privateKeys[j], previousHashedPoint));
            }
            token = pm.swap(previousMessage, token, hashedPoint, proofs);
            for (int j = 1; j < privateKeys.length; ++j) {
                token = token.add(hashedPoint.multiply(privateKeys[j]));
            }
            file.printf("%d\n", pm.cm.getLastTransmitTime());
        }
        file.close();
    }

}
