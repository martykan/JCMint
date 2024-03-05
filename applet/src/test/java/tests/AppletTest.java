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
    public AppletTest() {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
    }

    @Test
    public void setup() throws Exception {
        Random rnd = new Random();
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        for (byte parties = 1; parties < 4; ++parties) {
            BigInteger[] secrets = new BigInteger[parties];
            ECPoint[] points = new ECPoint[parties];
            for (int i = 0; i < parties; ++i) {
                BigInteger tmp;
                do {
                    tmp = new BigInteger(256, rnd);
                } while (tmp.toByteArray().length != 32);
                secrets[i] = tmp;
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

            CardManager cm = connect();
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
        }
    }

    @Test
    public void unknownInstruction() throws Exception {
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

}
