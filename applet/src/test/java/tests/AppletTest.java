package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import javacard.framework.ISO7816;
import jcmint.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AppletTest extends BaseTest {
    public AppletTest() {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
    }

    @Test
    public void unknownInstruction() throws Exception {
        CardManager cm = connect();
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                (byte) 0x00,
                (byte) 0x00,
                (byte) 0x00,
                new byte[0]
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(responseAPDU.getSW(), ISO7816.SW_INS_NOT_SUPPORTED);
    }

}
