package jcmint;

import javacard.framework.*;
import javacard.security.*;
import jcmint.jcmathlib.*;

public class JCMint extends Applet {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    public static ResourceManager rm;
    public static ECCurve curve;

    public byte index;
    public byte parties;
    public static BigNat secret;
    public static ECPoint mintKey;
    public static ECPoint[] partialKeys;

    private boolean initialized = false;
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JCMint(bArray, bOffset, bLength);
    }

    public JCMint(byte[] buffer, short offset, byte length) {
        OperationSupport.getInstance().setCard(CARD_TYPE);
        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        if (apdu.getBuffer()[ISO7816.OFFSET_CLA] != Consts.CLA_JCMINT)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        if (!initialized)
            initialize();

        try {
            switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
                case Consts.INS_SETUP:
                    setup(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Consts.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Consts.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Consts.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Consts.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Consts.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Consts.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Consts.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Consts.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Consts.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Consts.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Consts.SW_Exception);
        }
    }

    public boolean select() {
        if (initialized)
            curve.updateAfterReset();
        return true;
    }

    public void deselect() {}

    private void initialize() {
        if (initialized)
            ISOException.throwIt(Consts.E_ALREADY_INITIALIZED);

        rm = new ResourceManager((short) 256);
        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, rm);
        secret = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        mintKey = new ECPoint(curve);
        partialKeys = new ECPoint[Consts.MAX_PARTIES];
        for (short i = 0; i < Consts.MAX_PARTIES; ++i) {
            partialKeys[i] = new ECPoint(curve);
        }

        initialized = true;
    }

    private void setup(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        index = apduBuffer[ISO7816.OFFSET_P1];
        parties = apduBuffer[ISO7816.OFFSET_P2];
        if (parties < 1 || parties > Consts.MAX_PARTIES) {
            ISOException.throwIt(Consts.E_INVALID_PARTY_COUNT);
        }
        secret.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32);
        for (short i = 0; i < parties; ++i) {
            partialKeys[i].decode(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65 * i), (short) 65);
        }
        mintKey.copy(partialKeys[0]);
        for (short i = 1; i < parties; ++i) {
            mintKey.add(partialKeys[i]);
        }

        apdu.setOutgoingAndSend((short) 0, mintKey.getW(apduBuffer, (short) 0));
    }
}
