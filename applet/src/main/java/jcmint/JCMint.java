package jcmint;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import jcmint.jcmathlib.*;


/**
 * JCMint - A privacy-preserving digital currency implementation for smart cards.
 * Implements a multi-party minting system using elliptic curve cryptography.
 * Supports blind signatures, zero-knowledge proofs, and double-spending prevention.
 */
public class JCMint extends Applet implements ExtendedLength {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    // Core cryptographic infrastructure
    private ResourceManager rm;          // Memory management for big numbers
    private ECCurve curve;              // Elliptic curve operations (secp256k1)
    private final RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    // Multi-party setup state
    private byte index;                 // This card's index in the multi-party setup
    private byte parties;               // Total number of participating parties

    // Different coin denominations
    // NOTE: are multiple denominations actually supported?
    private Denomination[] denominations = new Denomination[1];

    // Temporary computation variables (reused to save memory)
    private ECPoint point1, point2;     // Temporary elliptic curve points
    private BigNat bn1, bn2;           // Temporary big number storage
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
    private final byte[] largeBuffer = JCSystem.makeTransientByteArray((short) 814, JCSystem.CLEAR_ON_RESET);
    private HashToCurve h2c;           // Hash-to-curve implementation

    // Double-spending prevention and verification state
    private final Ledger ledger = new Ledger();  // Tracks spent tokens
    private final byte[] verifying = new byte[(short) (32 + 65 + 65 + 65)]; // Verification context: (message, token, H(message), signature)
    private boolean initialized = false;
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JCMint(bArray, bOffset, bLength);
    }

    public JCMint(byte[] buffer, short offset, byte length) {
        OperationSupport.getInstance().setCard(CARD_TYPE);
        register();
    }

    /**
     * Main APDU processing method. Routes incoming commands to appropriate handlers.
     * Implements comprehensive error handling for debugging and security.
     */
    public void process(APDU apdu) {
        // Ignore SELECT commands
        if (selectingApplet())
            return;

        // Verify command class byte
        if (apdu.getBuffer()[ISO7816.OFFSET_CLA] != Consts.CLA_JCMINT)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        // Initialize on first use
        if (!initialized)
            initialize();

        try {
            // Route command based on instruction byte
            switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
                case Consts.INS_SETUP:
                    setup(apdu);           // Initialize multi-party keys
                    break;
                case Consts.INS_ISSUE:
                    issue(apdu);           // Issue partial signature
                    break;
                case Consts.INS_ISSUE_SINGLE_DLEQ:
                    issueSingleDLEQ(apdu);           // Issue signature with DLEQ
                    break;
                case Consts.INS_HASH_TO_CURVE:
                    hashToCurve(apdu);     // Hash data to curve point
                    break;
                case Consts.INS_VERIFY:
                    verify(apdu);          // Verify token and generate proof
                    break;
                case Consts.INS_SWAP:
                    swap(apdu);            // Swap token (multi-party)
                    break;
                case Consts.INS_SWAP_SINGLE:
                    swapSingle(apdu);      // Swap token (single-party)
                    break;
                case Consts.INS_REDEEM:
                    redeem(apdu);          // Redeem token (multi-party)
                    break;
                case Consts.INS_REDEEM_SINGLE:
                    redeemSingle(apdu);    // Redeem token (single-party)
                    break;
                case Consts.INS_NOP:
                    nop(apdu);             // No-operation (testing)
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Re-throw our own exceptions
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

    /**
     * Initializes the cryptographic infrastructure.
     * Sets up elliptic curve, memory management, and temporary variables.
     */
    private void initialize() {
        if (initialized)
            ISOException.throwIt(Consts.E_ALREADY_INITIALIZED);

        // Initialize memory management
        rm = new ResourceManager((short) 256);
        
        // Set up secp256k1 elliptic curve
        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, rm);
        h2c = new HashToCurve();

        // Initialize temporary computation variables
        point1 = new ECPoint(curve);
        point2 = new ECPoint(curve);
        bn1 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bn2 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);

        // Initialize denomination structures
        for (short i = 0; i < (short) denominations.length; ++i) {
            denominations[i] = new Denomination(rm);
        }

        initialized = true;
    }

    /**
     * Sets up the multi-party minting system.
     * Receives this card's secret and all parties' public keys.
     * Computes and returns the combined mint public key.
     */
    private void setup(APDU apdu) {
        byte[] buffer = loadApdu(apdu);
        index = buffer[ISO7816.OFFSET_P1];    // This card's index
        parties = buffer[ISO7816.OFFSET_P2];  // Total number of parties
        
        // Validate party count
        if (parties < 1 || parties > Consts.MAX_PARTIES) {
            ISOException.throwIt(Consts.E_INVALID_PARTY_COUNT);
        }
        
        // Initialize all denominations with the setup data
        // Data format: [secret_key][public_key_0][public_key_1]...[public_key_n]
        for (short i = 0; i < (short) denominations.length; ++i) {
            denominations[i].setup(parties, buffer, apdu.getOffsetCdata(), buffer, (short) (apdu.getOffsetCdata() + 32));
        }

        // Compute combined mint public key = sum of all party public keys
        ECPoint mintKey = point2;
        mintKey.decode(denominations[0].partialKeys, (short) 0, (short) 65);
        for (short i = 1; i < parties; ++i) {
            point1.decode(denominations[0].partialKeys, (short) (65 * i), (short) 65);
            mintKey.add(point1);
        }
        
        // Reset the spent token ledger
        ledger.reset();

        // Return the combined mint public key
        apdu.setOutgoingAndSend((short) 0, mintKey.getW(apdu.getBuffer(), (short) 0));
    }

    /**
     * Issues a partial blind signature on a challenge point.
     * Multiplies the challenge by this mint's secret key.
     * This is the core operation for token issuance.
     */
    private void issue(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte d = apduBuffer[ISO7816.OFFSET_P2];  // Denomination index

        // Decode the challenge point from client
        point1.decode(apduBuffer, ISO7816.OFFSET_CDATA, (short) 65);
        
        // Compute partial signature: challenge * secret_key
        point1.multiplication(denominations[d].secret);

        // Return the partial signature
        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }

    /**
     * Issues a blind signature on a challenge point including NUT-12 DLEQ.
     * Only available for single-party mode.
     */
    private void issueSingleDLEQ(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte d = apduBuffer[ISO7816.OFFSET_P2];  // Denomination index
        BigNat nonce = bn1;                      // Random nonce for proof
        BigNat tmp = bn2;                        // Temporary computation

        // Ensure single-party mode
        if (parties != 1)
            ISOException.throwIt(Consts.E_INVALID_PARTY_COUNT);

        // Generate random nonce for proof
        randomData.nextBytes(ramArray, (short) 0, (short) 32);
        nonce.fromByteArray(ramArray, (short) 0, (short) 32);

        // DLEQ proof step 1: Compute R1 = r*G
        point1.decode(curve.G, (short) 0, (short) curve.G.length);
        point1.multiplication(nonce);
        point1.encode(ramArray, (short) 0, false);
        md.reset();
        HexUtil.mdHexString(md, ramArray, (short) 0, (short) 65);

        // Decode the challenge point from client
        point1.decode(apduBuffer, ISO7816.OFFSET_CDATA, (short) 65);
        point2.decode(apduBuffer, ISO7816.OFFSET_CDATA, (short) 65);

        // DLEQ proof step 2: Compute R2 = r*B'
        point1.multiplication(nonce);
        point1.encode(ramArray, (short) 0, false);
        HexUtil.mdHexString(md, ramArray, (short) 0, (short) 65);

        // DLEQ proof step 3: Add A
        HexUtil.mdHexString(md, denominations[d].partialKeys, (short) (index * 65), (short) 65);

        // DLEQ proof step 4: Add C'
        point2.multiplication(denominations[d].secret);
        point2.encode(apduBuffer, (short) 0, false); // C'
        // Compute challenge e
        HexUtil.mdHexString(md, apduBuffer, (short) 0, (short) 65);
        md.doFinal(apduBuffer, (short) 0, (short) 0, apduBuffer, (short) 65);

        // DLEQ proof step 7: Compute response s = e * secret + nonce
        tmp.fromByteArray(apduBuffer, (short) 65, (short) 32);  // Load challenge e
        tmp.modMult(denominations[d].secret, curve.rBN);        // e * secret
        tmp.modAdd(nonce, curve.rBN);                           // + nonce
        tmp.copyToByteArray(apduBuffer, (short) (65 + 32));     // Store s

        // Return proof: [C_][e][s] (65 + 32 + 32 bytes)
        apdu.setOutgoingAndSend((short) 0, (short) (65 + 32 + 32));
    }

    /**
     * Converts arbitrary byte data to a valid elliptic curve point.
     * Uses deterministic hash-to-curve algorithm.
     */
    private void hashToCurve(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short length = apduBuffer[ISO7816.OFFSET_LC];

        // Hash the input data to a curve point
        h2c.hashLong(apduBuffer, ISO7816.OFFSET_CDATA, length, point1);
        
        // Return the resulting point
        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }


    /**
     * Verifies ownership of a token and generates a zero-knowledge proof.
     * Implements DLEQ (Discrete Log Equality) proof to prove knowledge of secret.
     * Also prevents double-spending by recording the message in the ledger.
     */
    private void verify(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte precomputed = apduBuffer[ISO7816.OFFSET_P1];  // Whether hash is precomputed
        BigNat nonce = bn1;                               // Random nonce for proof
        BigNat tmp = bn2;                                 // Temporary computation
        byte d = apduBuffer[ISO7816.OFFSET_P2];           // Denomination index

        // Prevent double-spending: check if message already used
        if (ledger.contains(apduBuffer, ISO7816.OFFSET_CDATA))
            ISOException.throwIt(Consts.E_ALREADY_SPENT);

        // Record message as spent
        ledger.append(apduBuffer, ISO7816.OFFSET_CDATA);
        
        // Store verification context: [message][token]
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, verifying, (short) 0, (short) (32 + 65));

        // DLEQ proof step 1: Compute X = H(message)
        if (precomputed == (byte) 1) {
            // Use precomputed hash-to-curve result
            h2c.hashPrecomputed(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65), point1);
        } else {
            // Compute hash-to-curve on the fly
            h2c.hash(apduBuffer, ISO7816.OFFSET_CDATA, point1);
        }

        // Store H(message) and start building hash for challenge
        point1.getW(verifying, (short) (32 + 65));
        md.reset();
        md.update(verifying, (short) (32 + 65), (short) 65);  // Add X to hash

        // DLEQ proof step 2: Compute Y = X * secret (the verifying point)
        point1.multiplication(denominations[d].secret);
        point1.getW(apduBuffer, (short) 0);                    // Store Y in output
        point1.getW(verifying, (short) (32 + 65 + 65));       // Store Y in context
        point1.decode(verifying, (short) (32 + 65), (short) 65); // Restore X
        md.update(apduBuffer, (short) 0, (short) 65);         // Add Y to hash

        // DLEQ proof step 3: Add generator P to hash
        point2.decode(curve.G, (short) 0, (short) curve.G.length);
        md.update(curve.G, (short) 0, (short) 65);

        // DLEQ proof step 4: Add public key Q to hash
        md.update(denominations[d].partialKeys, (short) (index * 65), (short) 65);

        // Generate random nonce for proof
        randomData.nextBytes(ramArray, (short) 0, (short) 32);
        nonce.fromByteArray(ramArray, (short) 0, (short) 32);

        // DLEQ proof step 5: Compute A = X * nonce
        point1.multiplication(nonce);
        point1.getW(ramArray, (short) 0);
        md.update(ramArray, (short) 0, (short) 65);  // Add A to hash

        // DLEQ proof step 6: Compute B = P * nonce  
        point2.multiplication(nonce);
        point2.getW(ramArray, (short) 0);
        md.doFinal(ramArray, (short) 0, (short) 65, apduBuffer, (short) 65);  // Compute challenge e

        // DLEQ proof step 7: Compute response s = e * secret + nonce
        tmp.fromByteArray(apduBuffer, (short) 65, (short) 32);  // Load challenge e
        tmp.modMult(denominations[d].secret, curve.rBN);        // e * secret
        tmp.modAdd(nonce, curve.rBN);                           // + nonce
        tmp.copyToByteArray(apduBuffer, (short) (65 + 32));     // Store s

        // Return proof: [Y][e][s] (65 + 32 + 32 bytes)
        apdu.setOutgoingAndSend((short) 0, (short) (65 + 32 + 32));
    }

    /**
     * Completes verification by checking all parties' zero-knowledge proofs.
     * Verifies DLEQ proofs from other parties and validates the complete token.
     * Used in multi-party swap and redeem operations.
     */
    private void finishVerify(byte d, byte[] token, short tokenOffset, byte[] proofs, short proofsOffset) {
        BigNat e = bn1;  // Challenge from proof
        BigNat s = bn2;  // Response from proof

        // Ensure we're verifying the same token as in verify()
        if (Util.arrayCompare(token, tokenOffset, verifying, (short) 0, (short) 32) != 0) {
            ISOException.throwIt(Consts.E_NOT_VERIFYING);
        }

        // Verify DLEQ proof from each other party
        for (short i = 0; i < parties; ++i) {
            if (i == index) {
                continue;  // Skip our own proof (already generated)
            }
            
            md.reset();
            
            // Extract proof components for party i
            e.fromByteArray(proofs, (short) (proofsOffset + i * (65 + 32 + 32) + 65), (short) 32);      // challenge
            s.fromByteArray(proofs, (short) (proofsOffset + i * (65 + 32 + 32) + 65 + 32), (short) 32); // response

            // Rebuild hash for challenge verification
            md.update(verifying, (short) (32 + 65), (short) 65);                     // X (hashed message)
            md.update(proofs, (short) (proofsOffset + i * (65 + 32 + 32)), (short) 65); // Y (verifying point)
            md.update(curve.G, (short) 0, (short) curve.G.length);                   // P (generator)
            md.update(denominations[d].partialKeys, (short) (65 * i), (short) 65);  // Q (public key)

            // Verify proof: recompute A = s*X - e*Y
            point2.decode(proofs, (short) (proofsOffset + i * (65 + 32 + 32)), (short) 65);  // Load Y
            point2.multiplication(e);   // e * Y
            point2.negate();           // -e * Y

            point1.decode(verifying, (short) (32 + 65), (short) 65);  // Load X
            point1.multAndAdd(s, point2);  // s*X + (-e*Y) = s*X - e*Y
            point1.getW(ramArray, (short) 0);
            md.update(ramArray, (short) 0, (short) 65);  // Add A to hash

            // Verify proof: recompute B = s*P - e*Q
            point2.decode(denominations[d].partialKeys, (short) (65 * i), (short) 65);  // Load Q
            point2.multiplication(e);   // e * Q
            point2.negate();           // -e * Q

            point1.decode(curve.G, (short) 0, (short) curve.G.length);  // Load P
            point1.multAndAdd(s, point2);  // s*P + (-e*Q) = s*P - e*Q
            point1.getW(ramArray, (short) 0);
            md.doFinal(ramArray, (short) 0, (short) 65, ramArray, (short) 0);  // Compute final hash

            // Check if recomputed challenge matches original
            if (Util.arrayCompare(proofs, (short) (proofsOffset + i * (65 + 32 + 32) + 65), ramArray, (short) 0, (short) 32) != 0) {
                ISOException.throwIt(Consts.E_VERIFICATION_FAILED_PROOF);
            }
        }

        // Verify the complete token by summing all verifying points
        point1.decode(verifying, (short) (32 + 65 + 65), (short) 65);  // Start with our verifying point
        for (short i = 0; i < parties; ++i) {
            if (i == index) {
                continue;  // Our contribution already included
            }
            // Add other parties' verifying points
            point2.decode(proofs, (short) (proofsOffset + i * (65 + 32 + 32)), (short) 65);
            point1.add(point2);
        }

        // Final verification: sum of verifying points should equal the provided token
        point1.getW(ramArray, (short) 0);
        if (Util.arrayCompare(ramArray, (short) 0, verifying, (short) 32, (short) 65) != 0) {
            ISOException.throwIt(Consts.E_VERIFICATION_FAILED_TOKEN);
        }

        // Clear verification context for security
        Util.arrayFillNonAtomic(verifying, (short) 0, (short) verifying.length, (byte) 0);
    }

    /**
     * Swaps an old token for a new one in multi-party mode.
     * First verifies the old token and all proofs, then issues new token.
     * Data format: [message][old_token][new_challenge][proofs...]
     */
    private void swap(APDU apdu) {
        byte[] buffer = loadApdu(apdu);
        byte d = buffer[ISO7816.OFFSET_P2];  // Denomination index

        // Verify old token and all parties' proofs
        finishVerify(d, buffer, apdu.getOffsetCdata(), buffer, (short) (apdu.getOffsetCdata() + 32 + 65 + 65));

        // Issue new token: new_challenge * secret
        point1.decode(buffer, (short) (apdu.getOffsetCdata() + 32 + 65), (short) 65);  // Load new challenge
        point1.multiplication(denominations[d].secret);
        
        // Return new partial signature
        apdu.setOutgoingAndSend((short) 0, point1.getW(apdu.getBuffer(), (short) 0));
    }

    /**
     * Swaps a token in single-party mode (simpler, no external proofs needed).
     * Verifies old token locally and issues new token.
     * Data format: [message][old_token][new_challenge][optional_precomputed_hash]
     */
    private void swapSingle(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte precomputed = apduBuffer[ISO7816.OFFSET_P1];  // Precomputed hash flag
        byte d = apduBuffer[ISO7816.OFFSET_P2];            // Denomination index
        short messageLength = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xff - 130);
        if (precomputed == (byte) 1) {
            messageLength = (short) (messageLength - 65);
        }

        // Ensure single-party mode
        if (parties != 1)
            ISOException.throwIt(Consts.E_INVALID_PARTY_COUNT);

        // Prevent double-spending
        if (ledger.contains(apduBuffer, ISO7816.OFFSET_CDATA))
            ISOException.throwIt(Consts.E_ALREADY_SPENT);

        // Compute or load H(message)
        if (precomputed == (byte) 1 && messageLength == (short) 32) {
            // Use precomputed hash provided in command data
            h2c.hashPrecomputed(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65 + 65), point1);
        } else {
            // Compute hash on the fly
            h2c.hashLong(apduBuffer, ISO7816.OFFSET_CDATA, messageLength, point1);
        }
        
        // Verify old token: should be H(message) * secret
        point1.multiplication(denominations[d].secret);
        point1.getW(ramArray, (short) 0);
        
        // Compare computed token with provided token
        if (Util.arrayCompare(apduBuffer, (short) (ISO7816.OFFSET_CDATA + messageLength), ramArray, (short) 0, (short) 65) != 0)
            ISOException.throwIt(Consts.E_VERIFICATION_FAILED_TOKEN);

        // Mark message as spent
        ledger.append(apduBuffer, ISO7816.OFFSET_CDATA);
        
        // Issue new token: new_challenge * secret
        point1.decode(apduBuffer, (short) (ISO7816.OFFSET_CDATA + messageLength + 65), (short) 65);
        point1.multiplication(denominations[d].secret);
        
        // Return new token
        apdu.setOutgoingAndSend((short) 0, point1.getW(apduBuffer, (short) 0));
    }

    /**
     * Redeems a token in multi-party mode.
     * Verifies the token and all parties' proofs, then marks token as spent.
     * Data format: [message][token][proofs...]
     */
    private void redeem(APDU apdu) {
        byte[] buffer = loadApdu(apdu);
        byte d = buffer[ISO7816.OFFSET_P2];  // Denomination index

        // Verify token and all parties' proofs
        finishVerify(d, buffer, apdu.getOffsetCdata(), buffer, (short) (apdu.getOffsetCdata() + 32 + 65));

        // Return success (no data)
        apdu.setOutgoing();
    }

    /**
     * Redeems a token in single-party mode.
     * Verifies token locally and marks it as spent.
     * Data format: [message][token][optional_precomputed_hash]
     */
    private void redeemSingle(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte precomputed = apduBuffer[ISO7816.OFFSET_P1];  // Precomputed hash flag
        byte d = apduBuffer[ISO7816.OFFSET_P2];            // Denomination index

        // Ensure single-party mode
        if (parties != 1)
            ISOException.throwIt(Consts.E_INVALID_PARTY_COUNT);

        // Prevent double-spending
        if (ledger.contains(apduBuffer, ISO7816.OFFSET_CDATA))
            ISOException.throwIt(Consts.E_ALREADY_SPENT);

        // Compute or load H(message)
        if (precomputed == (byte) 1) {
            // Use precomputed hash provided in command data
            h2c.hashPrecomputed(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32 + 65), point1);
        } else {
            // Compute hash on the fly
            h2c.hash(apduBuffer, ISO7816.OFFSET_CDATA, point1);
        }
        
        // Verify token: should be H(message) * secret
        point1.multiplication(denominations[d].secret);
        point1.getW(ramArray, (short) 0);
        
        // Compare computed token with provided token
        if (Util.arrayCompare(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), ramArray, (short) 0, (short) 65) != 0)
            ISOException.throwIt(Consts.E_VERIFICATION_FAILED_TOKEN);

        // Mark message as spent
        ledger.append(apduBuffer, ISO7816.OFFSET_CDATA);
        
        // Return success (no data)
        apdu.setOutgoing();
    }

    /**
     * No-operation command for testing and benchmarking.
     * Returns specified amount of dummy data for performance testing.
     */
    private void nop(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0xff);  // Output size
        
        // Return p1 bytes of data (buffer content doesn't matter for testing)
        apdu.setOutgoingAndSend((short) 0, p1);
    }

    /**
     * Loads APDU data, handling both standard and extended length APDUs.
     * For extended APDUs, data is copied to a larger buffer.
     * 
     * @param apdu The APDU to load data from
     * @return Buffer containing the complete APDU data
     */
    private byte[] loadApdu(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short recvLen = (short) (apdu.setIncomingAndReceive() + apdu.getOffsetCdata());
        
        // For standard APDUs, return the original buffer
        if (apdu.getOffsetCdata() == ISO7816.OFFSET_CDATA) {
            return apduBuffer;
        }
        
        // For extended APDUs, copy data to large buffer
        short written = 0;
        while (recvLen > 0) {
            Util.arrayCopyNonAtomic(apduBuffer, (short) 0, largeBuffer, written, recvLen);
            written += recvLen;
            recvLen = apdu.receiveBytes((short) 0);  // Receive next chunk
        }
        return largeBuffer;
    }
}
