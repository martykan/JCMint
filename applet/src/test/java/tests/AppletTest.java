package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.ISO7816;
import jcmint.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.util.Random;

public class AppletTest extends BaseTest {
    private final Random rnd = new Random();
    private final ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    public AppletTest() {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
    }

    public ECPoint setup(CardManager cm, int parties) throws Exception {
        BigInteger[] secrets = new BigInteger[parties];
        ECPoint[] points = new ECPoint[parties];
        for (int i = 0; i < parties; ++i) {
            secrets[i] = randomBigInt(32);
            points[i] = ecSpec.getG().multiply(secrets[i]);
        }
        ECPoint mintKey = points[0];
        for (int i = 1; i < parties; ++i) {
            mintKey = mintKey.add(points[i]);
        }
        byte[] data = secrets[0].toByteArray();
        for (int i = 0; i < parties; ++i) {
            data = Util.concat(data, points[i].getEncoded(false));
        }

        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_SETUP,
                (byte) 0, // card index
                parties,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        Assertions.assertArrayEquals(mintKey.getEncoded(false), responseAPDU.getData());
        return mintKey;
    }

    @Test
    public void testSetup() throws Exception {
        CardManager cm = connect();
        for (int parties = 1; parties <= Consts.MAX_PARTIES; ++parties) {
            setup(cm, parties);
        }
    }

    @Test
    public void testIssue() throws Exception {
        CardManager cm = connect();
        ECPoint mintKey = setup(cm, 1);

        BigInteger scalar = randomBigInt(32);
        ECPoint challenge = ecSpec.getG().multiply(scalar);
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
        Assertions.assertArrayEquals(mintKey.multiply(scalar).getEncoded(false), responseAPDU.getData());
        // TODO test with more than 1 party requires checking against partial keys
    }

    @Test
    public void testUnknownInstruction() throws Exception {
        CardManager cm = connect();
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                (byte) 0x12,
                (byte) 0x34,
                (byte) 0x56,
                new byte[0]
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(responseAPDU.getSW(), ISO7816.SW_INS_NOT_SUPPORTED);
    }

    private BigInteger randomBigInt(int bytes) {
        BigInteger tmp;
        do {
            tmp = new BigInteger(bytes * 8, rnd);
        } while (tmp.toByteArray().length != bytes);
        return tmp;
    }
}
