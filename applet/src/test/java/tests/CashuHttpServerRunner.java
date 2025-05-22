package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.junit.jupiter.api.Test;

public class CashuHttpServerRunner extends BaseTest {
    public CashuHttpServerRunner() {
        setCardType(CardType.JCARDSIMLOCAL);
    }

    @Test
    public void run() throws Exception {
        int port = 8080;
        byte cardIndex = 0;

        CardManager cardManager = connect();
        CashuHttpServer server = new CashuHttpServer(port, cardManager, cardIndex);
        server.startServer();
    }
}
