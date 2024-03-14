package jcmint;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import jcmint.jcmathlib.*;


public class JCMint extends Applet implements ExtendedLength {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    private ResourceManager rm;
    private ECCurve curve;
    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    private final RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    private byte index;
    private byte parties;
    private BigNat secret;
    private byte[] partialKeys;

    private ECPoint point1, point2;
    private BigNat bn1, bn2;
    private final byte[] prefixBuffer = JCSystem.makeTransientByteArray((short) 36, JCSystem.CLEAR_ON_RESET);
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
    private final byte[] largeBuffer = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_RESET);

    private final Ledger ledger = new Ledger();
    private final byte[] verifying = new byte[(short) (32 + 65 + 65)]; // (x, C, H(x))
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
                case Consts.INS_ISSUE:
                    issue(apdu);
                    break;
                case Consts.INS_HASH_TO_CURVE:
                    hashToCurve(apdu);
                    break;
                case Consts.INS_VERIFY:
                    verify(apdu);
                    break;
                case Consts.INS_SWAP:
                    swap(apdu);
                    break;
                case Consts.INS_SWAP_SINGLE:
                    swapSingle(apdu);
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
        partialKeys = new byte[65 * Consts.MAX_PARTIES];
        point1 = new ECPoint(curve);
        point2 = new ECPoint(curve);
        bn1 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bn2 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);

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
        Util.arrayCopyNonAtomic(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), partialKeys, (short) 0, (short) (65 * parties));

        ECPoint mintKey = point2;

        mintKey.decode(partialKeys, (short) 0, (short) 65);
        for (short i = 1; i < parties; ++i) {
            point1.decode(partialKeys, (short) (65 * i), (short) 65);
            mintKey.add(point1);
        }
        ledger.reset();

        apdu.setOutgoingAndSend((short) 0, mintKey.getW(apduBuffer, (short) 0));
    }

    private void issue(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        point1.decode(apduBuffer, ISO7816.OFFSET_CDATA, (short) 65);
        point1.multiplication(secret);

        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }

    private void hashToCurve(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        h2c(apduBuffer, ISO7816.OFFSET_CDATA);
        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }

    private void h2c(byte[] data, short offset) {
        Util.arrayFillNonAtomic(prefixBuffer, (short) 32, (short) 4, (byte) 0);
        md.reset();
        md.update(Consts.H2C_DOMAIN_SEPARATOR, (short) 0, (short) Consts.H2C_DOMAIN_SEPARATOR.length);
        md.doFinal(data, offset, (short) 32, prefixBuffer, (short) 0);

        for (short counter = 0; counter < (short) 256; ++counter) { // TODO consider increasing max number of iters
            md.reset();
            prefixBuffer[32] = (byte) (counter & 0xff);
            md.doFinal(prefixBuffer, (short) 0, (short) prefixBuffer.length, ramArray, (short) 0);
            if (point1.fromX(ramArray, (short) 0, (short) 32))
                break;
        }
        if (!point1.isYEven())
            point1.negate();
    }

    private void verify(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        BigNat nonce = bn1;
        BigNat tmp = bn2;

        if (ledger.contains(apduBuffer, ISO7816.OFFSET_CDATA))
            ISOException.throwIt(Consts.E_ALREADY_SPENT);

        ledger.append(apduBuffer, ISO7816.OFFSET_CDATA);
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, verifying, (short) 0, (short) (32 + 65));

        md.reset();

        // DLEQ X
        h2c(apduBuffer, ISO7816.OFFSET_CDATA);
        point1.getW(verifying, (short) (32 + 65));
        md.update(verifying, (short) (32 + 65), (short) 65);

        // DLEQ Y
        point1.multiplication(secret);
        point1.getW(apduBuffer, (short) 0);
        point1.decode(verifying, (short) (32 + 65), (short) 65); // restore hashOutput
        md.update(apduBuffer, (short) 0, (short) 65);

        // DLEQ P
        point2.decode(curve.G, (short) 0, (short) curve.G.length);
        md.update(curve.G, (short) 0, (short) 65);

        // DLEQ Q
        md.update(partialKeys, (short) (index * 65), (short) 65);

        randomData.nextBytes(ramArray, (short) 0, (short) 32);
        nonce.fromByteArray(ramArray, (short) 0, (short) 32);

        // DLEQ A
        point1.multiplication(nonce);
        point1.getW(ramArray, (short) 0);
        md.update(ramArray, (short) 0, (short) 65);

        // DLEQ B
        point2.multiplication(nonce);
        point2.getW(ramArray, (short) 0);
        md.doFinal(ramArray, (short) 0, (short) 65, apduBuffer, (short) 65);

        tmp.fromByteArray(apduBuffer, (short) 65, (short) 32);
        tmp.modMult(secret, curve.rBN);
        tmp.modAdd(nonce, curve.rBN);
        tmp.copyToByteArray(apduBuffer, (short) (65 + 32));

        apdu.setOutgoingAndSend((short) 0, (short) (65 + 32 + 32));
    }

    private void swap(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short recvLen = (short) (apdu.setIncomingAndReceive() + ISO7816.OFFSET_EXT_CDATA);
        short written = 0;
        while (recvLen > 0) {
            Util.arrayCopyNonAtomic(apduBuffer, (short) 0, largeBuffer, written, recvLen);
            written += recvLen;
            recvLen = apdu.receiveBytes((short) 0);
        }
        apduBuffer = largeBuffer;

        BigNat e = bn1;
        BigNat s = bn2;

        if (Util.arrayCompare(apduBuffer, ISO7816.OFFSET_EXT_CDATA, verifying, (short) 0, (short) 32) != 0) {
            ISOException.throwIt(Consts.E_NOT_VERIFYING);
        }

        for (short i = 0; i < parties; ++i) {
            md.reset();
            e.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_EXT_CDATA + 32 + 65 + 65 + i * (65 + 32 + 32) + 65), (short) 32); // e
            s.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_EXT_CDATA + 32 + 65 + 65 + i * (65 + 32 + 32) + 65 + 32), (short) 32); // s

            md.update(verifying, (short) (32 + 65), (short) 65); // X
            md.update(apduBuffer, (short) (ISO7816.OFFSET_EXT_CDATA + 32 + 65 + 65 + i * (65 + 32 + 32)), (short) 65); // Y
            md.update(curve.G, (short) 0, (short) curve.G.length); // P
            md.update(partialKeys, (short) (65 * i), (short) 65); // Q

            // compute A
            point2.decode(apduBuffer, (short) (ISO7816.OFFSET_EXT_CDATA + 32 + 65 + 65 + i * (65 + 32 + 32)), (short) 65);
            point2.multiplication(e);
            point2.negate();

            point1.decode(verifying, (short) (32 + 65), (short) 65); // reload hash output
            point1.multAndAdd(s, point2);
            point1.getW(ramArray, (short) 0);
            md.update(ramArray, (short) 0, (short) 65); // A

            // compute B
            point2.decode(partialKeys, (short) (65 * i), (short) 65);
            point2.multiplication(e);
            point2.negate();

            point1.decode(curve.G, (short) 0, (short) curve.G.length);
            point1.multAndAdd(s, point2);
            point1.getW(ramArray, (short) 0);
            md.doFinal(ramArray, (short) 0, (short) 65, ramArray, (short) 0); // B

            if (Util.arrayCompare(apduBuffer, (short) (ISO7816.OFFSET_EXT_CDATA + 32 + 65 + 65 + i * (65 + 32 + 32) + 65), ramArray, (short) 0, (short) 32) != 0) {
                ISOException.throwIt(Consts.E_VERIFICATION_FAILED_PROOF);
            }
        }

        point1.decode(apduBuffer, (short) (ISO7816.OFFSET_EXT_CDATA + 32 + 65 + 65), (short) 65);
        for (short i = 1; i < parties; ++i) {
            point2.decode(apduBuffer, (short) (ISO7816.OFFSET_EXT_CDATA + 32 + 65 + 65 + i * (65 + 32 + 32)), (short) 65);
            point1.add(point2);
        }

        point1.getW(ramArray, (short) 0);
        if (Util.arrayCompare(ramArray, (short) 0, verifying, (short) 32, (short) 65) != 0) {
            ISOException.throwIt(Consts.E_VERIFICATION_FAILED_TOKEN);
        }

        Util.arrayFillNonAtomic(verifying, (short) 0, (short) verifying.length, (byte) 0);

        point1.decode(apduBuffer, (short) (ISO7816.OFFSET_EXT_CDATA + 32 + 65), (short) 65);
        point1.multiplication(secret);
        apdu.setOutgoingAndSend((short) 0, point1.getW(apdu.getBuffer(), (short) 0));
    }

    private void swapSingle(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if (parties != 1)
            ISOException.throwIt(Consts.E_INVALID_PARTY_COUNT);

        if (ledger.contains(apduBuffer, ISO7816.OFFSET_CDATA))
            ISOException.throwIt(Consts.E_ALREADY_SPENT);

        h2c(apduBuffer, ISO7816.OFFSET_CDATA);
        point1.multiplication(secret);

        point1.getW(ramArray, (short) 0);
        if (Util.arrayCompare(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), ramArray, (short) 0, (short) 65) != 0)
            ISOException.throwIt(Consts.E_VERIFICATION_FAILED_TOKEN);

        ledger.append(apduBuffer, ISO7816.OFFSET_CDATA);
        point1.decode(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65), (short) 65);
        point1.multiplication(secret);
        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }
}
