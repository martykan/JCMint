package jcmint;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import jcmint.jcmathlib.*;


public class JCMint extends Applet implements ExtendedLength {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    private ResourceManager rm;
    private ECCurve curve;
    private final RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    private byte index;
    private byte parties;
    private Denomination[] denominations = new Denomination[1];

    private ECPoint point1, point2;
    private BigNat bn1, bn2;
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
    private final byte[] largeBuffer = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_RESET);
    private HashToCurve h2c;

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
                case Consts.INS_REDEEM:
                    redeem(apdu);
                    break;
                case Consts.INS_REDEEM_SINGLE:
                    redeemSingle(apdu);
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
        h2c = new HashToCurve();

        point1 = new ECPoint(curve);
        point2 = new ECPoint(curve);
        bn1 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bn2 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);

        for (int i = 0; i < (short) denominations.length; ++i) {
            denominations[i] = new Denomination(rm);
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
        for (short i = 0; i < (short) denominations.length; ++i) {
            denominations[i].setup(parties, apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32));
        }

        ECPoint mintKey = point2;

        mintKey.decode(denominations[0].partialKeys, (short) 0, (short) 65);
        for (short i = 1; i < parties; ++i) {
            point1.decode(denominations[0].partialKeys, (short) (65 * i), (short) 65);
            mintKey.add(point1);
        }
        ledger.reset();

        apdu.setOutgoingAndSend((short) 0, mintKey.getW(apduBuffer, (short) 0));
    }

    private void issue(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte d = apduBuffer[ISO7816.OFFSET_P2];

        point1.decode(apduBuffer, ISO7816.OFFSET_CDATA, (short) 65);
        point1.multiplication(denominations[d].secret);

        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }

    private void hashToCurve(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        h2c.hash(apduBuffer, ISO7816.OFFSET_CDATA, point1);
        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }


    private void verify(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte precomputed = apduBuffer[ISO7816.OFFSET_P1];
        BigNat nonce = bn1;
        BigNat tmp = bn2;
        byte d = apduBuffer[ISO7816.OFFSET_P2];

        if (ledger.contains(apduBuffer, ISO7816.OFFSET_CDATA))
            ISOException.throwIt(Consts.E_ALREADY_SPENT);

        ledger.append(apduBuffer, ISO7816.OFFSET_CDATA);
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, verifying, (short) 0, (short) (32 + 65));

        // DLEQ X
        if (precomputed == (byte) 1) {
            h2c.hashPrecomputed(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65), point1);
        } else {
            h2c.hash(apduBuffer, ISO7816.OFFSET_CDATA, point1);
        }

        point1.getW(verifying, (short) (32 + 65));
        md.reset();
        md.update(verifying, (short) (32 + 65), (short) 65);

        // DLEQ Y
        point1.multiplication(denominations[d].secret);
        point1.getW(apduBuffer, (short) 0);
        point1.decode(verifying, (short) (32 + 65), (short) 65); // restore hashOutput
        md.update(apduBuffer, (short) 0, (short) 65);

        // DLEQ P
        point2.decode(curve.G, (short) 0, (short) curve.G.length);
        md.update(curve.G, (short) 0, (short) 65);

        // DLEQ Q
        md.update(denominations[d].partialKeys, (short) (index * 65), (short) 65);

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
        tmp.modMult(denominations[d].secret, curve.rBN);
        tmp.modAdd(nonce, curve.rBN);
        tmp.copyToByteArray(apduBuffer, (short) (65 + 32));

        apdu.setOutgoingAndSend((short) 0, (short) (65 + 32 + 32));
    }

    private void finishVerify(byte d, byte[] token, short tokenOffset, byte[] proofs, short proofsOffset) {
        BigNat e = bn1;
        BigNat s = bn2;

        if (Util.arrayCompare(token, tokenOffset, verifying, (short) 0, (short) 32) != 0) {
            ISOException.throwIt(Consts.E_NOT_VERIFYING);
        }

        for (short i = 0; i < parties; ++i) {
            md.reset();
            e.fromByteArray(proofs, (short) (proofsOffset + i * (65 + 32 + 32) + 65), (short) 32); // e
            s.fromByteArray(proofs, (short) (proofsOffset + i * (65 + 32 + 32) + 65 + 32), (short) 32); // s

            md.update(verifying, (short) (32 + 65), (short) 65); // X
            md.update(proofs, (short) (proofsOffset + i * (65 + 32 + 32)), (short) 65); // Y
            md.update(curve.G, (short) 0, (short) curve.G.length); // P
            md.update(denominations[d].partialKeys, (short) (65 * i), (short) 65); // Q

            // compute A
            point2.decode(proofs, (short) (proofsOffset + i * (65 + 32 + 32)), (short) 65);
            point2.multiplication(e);
            point2.negate();

            point1.decode(verifying, (short) (32 + 65), (short) 65); // reload hash output
            point1.multAndAdd(s, point2);
            point1.getW(ramArray, (short) 0);
            md.update(ramArray, (short) 0, (short) 65); // A

            // compute B
            point2.decode(denominations[d].partialKeys, (short) (65 * i), (short) 65);
            point2.multiplication(e);
            point2.negate();

            point1.decode(curve.G, (short) 0, (short) curve.G.length);
            point1.multAndAdd(s, point2);
            point1.getW(ramArray, (short) 0);
            md.doFinal(ramArray, (short) 0, (short) 65, ramArray, (short) 0); // B

            if (Util.arrayCompare(proofs, (short) (proofsOffset + i * (65 + 32 + 32) + 65), ramArray, (short) 0, (short) 32) != 0) {
                ISOException.throwIt(Consts.E_VERIFICATION_FAILED_PROOF);
            }
        }

        point1.decode(proofs, proofsOffset, (short) 65);
        for (short i = 1; i < parties; ++i) {
            point2.decode(proofs, (short) (proofsOffset + i * (65 + 32 + 32)), (short) 65);
            point1.add(point2);
        }

        point1.getW(ramArray, (short) 0);
        if (Util.arrayCompare(ramArray, (short) 0, verifying, (short) 32, (short) 65) != 0) {
            ISOException.throwIt(Consts.E_VERIFICATION_FAILED_TOKEN);
        }

        Util.arrayFillNonAtomic(verifying, (short) 0, (short) verifying.length, (byte) 0);
    }

    private void swap(APDU apdu) {
        loadExtendedApdu(apdu);
        byte d = largeBuffer[ISO7816.OFFSET_P2];

        finishVerify(d, largeBuffer, apdu.getOffsetCdata(), largeBuffer, (short) (apdu.getOffsetCdata() + 32 + 65 + 65));

        point1.decode(largeBuffer, (short) (apdu.getOffsetCdata() + 32 + 65), (short) 65);
        point1.multiplication(denominations[d].secret);
        apdu.setOutgoingAndSend((short) 0, point1.getW(apdu.getBuffer(), (short) 0));
    }

    private void swapSingle(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte precomputed = apduBuffer[ISO7816.OFFSET_P1];
        byte d = apduBuffer[ISO7816.OFFSET_P2];

        if (parties != 1)
            ISOException.throwIt(Consts.E_INVALID_PARTY_COUNT);

        if (ledger.contains(apduBuffer, ISO7816.OFFSET_CDATA))
            ISOException.throwIt(Consts.E_ALREADY_SPENT);

        if (precomputed == (byte) 1) {
            h2c.hashPrecomputed(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65 + 65), point1);
        } else {
            h2c.hash(apduBuffer, ISO7816.OFFSET_CDATA, point1);
        }
        point1.multiplication(denominations[d].secret);

        point1.getW(ramArray, (short) 0);
        if (Util.arrayCompare(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), ramArray, (short) 0, (short) 65) != 0)
            ISOException.throwIt(Consts.E_VERIFICATION_FAILED_TOKEN);

        ledger.append(apduBuffer, ISO7816.OFFSET_CDATA);
        point1.decode(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65), (short) 65);
        point1.multiplication(denominations[d].secret);
        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }

    private void redeem(APDU apdu) {
        loadExtendedApdu(apdu);
        byte d = largeBuffer[ISO7816.OFFSET_P2];

        finishVerify(d, largeBuffer, apdu.getOffsetCdata(), largeBuffer, (short) (apdu.getOffsetCdata() + 32 + 65));

        apdu.setOutgoing();
    }

    private void redeemSingle(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte precomputed = apduBuffer[ISO7816.OFFSET_P1];
        byte d = apduBuffer[ISO7816.OFFSET_P2];

        if (parties != 1)
            ISOException.throwIt(Consts.E_INVALID_PARTY_COUNT);

        if (ledger.contains(apduBuffer, ISO7816.OFFSET_CDATA))
            ISOException.throwIt(Consts.E_ALREADY_SPENT);

        if (precomputed == (byte) 1) {
            h2c.hashPrecomputed(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65), point1);
        } else {
            h2c.hash(apduBuffer, ISO7816.OFFSET_CDATA, point1);
        }
        point1.multiplication(denominations[d].secret);

        point1.getW(ramArray, (short) 0);
        if (Util.arrayCompare(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), ramArray, (short) 0, (short) 65) != 0)
            ISOException.throwIt(Consts.E_VERIFICATION_FAILED_TOKEN);

        ledger.append(apduBuffer, ISO7816.OFFSET_CDATA);
        apdu.setOutgoing();
    }

    private short loadExtendedApdu(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short recvLen = (short) (apdu.setIncomingAndReceive() + apdu.getOffsetCdata());
        short written = 0;
        while (recvLen > 0) {
            Util.arrayCopyNonAtomic(apduBuffer, (short) 0, largeBuffer, written, recvLen);
            written += recvLen;
            recvLen = apdu.receiveBytes((short) 0);
        }
        return written;
    }
}
