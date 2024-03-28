package tests;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

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
        PrintWriter file = new PrintWriter(new FileWriter(precomputed ? "swap_single_precomputed.csv" : "swap_single.csv", false));
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

}
