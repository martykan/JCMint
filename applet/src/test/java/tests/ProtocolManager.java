package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.ISO7816;
import jcmint.Consts;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

/**
 * Protocol manager for communicating with the JCMint smart card applet.
 * Handles APDU command construction and response parsing for all minting operations.
 * Acts as a client-side interface to the cryptographic minting protocol.
 */
public class ProtocolManager {
    // Card manager for APDU communication
    public final CardManager cm;

    // Elliptic curve parameters (secp256k1 - same as Bitcoin)
    private final static ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    public final static ECPoint G = ecSpec.getG();  // Generator point
    private final static Random rnd = new Random();
    
    // Index of this card in multi-party setup
    private byte card_idx;

    /**
     * Creates a new protocol manager for communicating with a specific card.
     * @param cm CardManager for APDU communication
     * @param card_idx Index of this card in the multi-party setup
     */
    public ProtocolManager(CardManager cm, byte card_idx) {
        this.cm = cm;
        this.card_idx = card_idx;
    }

    /**
     * Sets up the multi-party minting system by generating secrets and public keys.
     * Each party generates a random secret, computes its public key, and shares the public keys.
     * The combined mint public key is the sum of all individual public keys.
     * 
     * @param secrets Array to store generated secrets for all parties
     * @return The combined mint public key (sum of all party public keys)
     */
    public ECPoint setup(BigInteger[] secrets) throws Exception {
        ECPoint[] points = new ECPoint[secrets.length];
        
        // Generate random secret keys for all parties
        for (int i = 0; i < secrets.length; ++i) {
            secrets[i] = randomBigInt(32);
            points[i] = ecSpec.getG().multiply(secrets[i]);  // Public key = G * secret
        }
        
        // Compute combined mint public key = sum of all public keys
        ECPoint mintKey = points[0];
        for (int i = 1; i < secrets.length; ++i) {
            mintKey = mintKey.add(points[i]);
        }
        
        // Prepare data: this card's secret + all public keys
        byte[] data = encodeBigInteger(secrets[card_idx]);
        for (int i = 0; i < secrets.length; ++i) {
            data = Util.concat(data, points[i].getEncoded(false));
        }

        // Send setup command to card
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_SETUP,
                card_idx,                    // P1: This card's index
                (byte) secrets.length,       // P2: Number of parties
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        
        // Card should return the same combined mint key
        Assertions.assertArrayEquals(mintKey.getEncoded(false), responseAPDU.getData());
        return mintKey;
    }

    /**
     * Converts arbitrary byte data to a valid elliptic curve point.
     * Uses a deterministic hash-to-curve algorithm for consistent results.
     * 
     * @param input The byte data to hash to a curve point
     * @return A valid point on the elliptic curve
     */
    public ECPoint hashToCurve(byte[] input) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_HASH_TO_CURVE,
                (byte) 0,    // P1: unused
                (byte) 0,    // P2: unused
                input        // Data to hash
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        
        // Decode the returned point
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }

    /**
     * Issues a partial signature on a challenge point.
     * This is used in the blinded signature protocol for token issuance.
     * The card multiplies the challenge by its secret key.
     * 
     * @param challenge The challenge point to sign
     * @return Partial signature: challenge * this_mint_secret
     */
    public ECPoint issue(ECPoint challenge) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_ISSUE,
                (byte) 0,    // P1: unused
                (byte) 0,    // P2: denomination (default 0)
                challenge.getEncoded(false)  // Challenge point to sign
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        
        // Return the partial signature
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }

    /**
     * Verifies ownership of a token and generates a zero-knowledge proof.
     * This proves knowledge of the secret without revealing it.
     * Also prevents double-spending by recording the message in the ledger.
     * 
     * @param message The message/nonce being verified (prevents replay)
     * @param token The token being verified
     * @param precomputed Optional precomputed hash-to-curve result for optimization
     * @return Zero-knowledge proof of ownership
     */
    public byte[] verify(byte[] message, ECPoint token, ECPoint precomputed) throws Exception {
        // Prepare command data: message + token + optional precomputed hash
        byte[] data = Util.concat(message, token.getEncoded(false));
        if (precomputed != null) {
            data = Util.concat(data, precomputed.getEncoded(false));
        }
        
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_VERIFY,
                (byte) (precomputed == null ? 0 : 1),  // P1: precomputed flag
                (byte) 0,                              // P2: denomination
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        
        // Return the zero-knowledge proof
        return responseAPDU.getData();
    }

    /**
     * Swaps an old token for a new one with a different challenge point.
     * Verifies the old token is valid and issues a new token.
     * Used in multi-party scenarios where multiple proofs are required.
     * 
     * @param message The message being used for this swap
     * @param token The old token being exchanged
     * @param challenge The new challenge point for the new token
     * @param proofs Zero-knowledge proofs from all parties
     * @return New token: challenge * this_mint_secret
     */
    public ECPoint swap(byte[] message, ECPoint token, ECPoint challenge, byte[] proofs) throws Exception {
        // Prepare command data: message + old_token + new_challenge + proofs
        byte[] data = Util.concat(message, token.getEncoded(false), challenge.getEncoded(false));
        data = Util.concat(data, proofs);
        
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_SWAP,
                (byte) 0,    // P1: unused
                (byte) 0,    // P2: denomination
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        
        // Return the new token
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }


    /**
     * Redeems a token, proving its validity and marking it as spent.
     * Used in multi-party scenarios where multiple proofs are required.
     * The token is destroyed in the process (added to spent list).
     * 
     * @param message The message being used for this redemption
     * @param token The token being redeemed
     * @param proofs Zero-knowledge proofs from all parties
     * @return true if redemption was successful
     */
    public boolean redeem(byte[] message, ECPoint token, byte[] proofs) throws Exception {
        // Prepare command data: message + token + proofs
        byte[] data = Util.concat(message, token.getEncoded(false), proofs);
        
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_REDEEM,
                (byte) 0,    // P1: unused
                (byte) 0,    // P2: denomination
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        
        // Redemption returns no data (just success/failure)
        Assertions.assertArrayEquals(new byte[0], responseAPDU.getData());
        return true;
    }

    /**
     * Swaps a token in single-party mode (no external proofs needed).
     * Simpler version of swap for when only one mint is involved.
     * 
     * @param message The message being used for this swap
     * @param token The old token being exchanged
     * @param challenge The new challenge point for the new token
     * @param precomputed Optional precomputed hash-to-curve result
     * @return New token: challenge * this_mint_secret
     */
    public ECPoint swapSingle(byte[] message, ECPoint token, ECPoint challenge, ECPoint precomputed) throws Exception {
        // Prepare command data: message + old_token + new_challenge + optional precomputed
        byte[] data = Util.concat(message, token.getEncoded(false), challenge.getEncoded(false));
        if (precomputed != null) {
            data = Util.concat(data, precomputed.getEncoded(false));
        }

        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_SWAP_SINGLE,
                (byte) (precomputed == null ? 0 : 1),  // P1: precomputed flag
                (byte) 0,                              // P2: denomination
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        
        // Return the new token
        return ecSpec.getCurve().decodePoint(responseAPDU.getData());
    }

    /**
     * Redeems a token in single-party mode (no external proofs needed).
     * Simpler version of redeem for when only one mint is involved.
     * 
     * @param message The message being used for this redemption
     * @param token The token being redeemed
     * @param precomputed Optional precomputed hash-to-curve result
     * @return true if redemption was successful
     */
    public boolean redeemSingle(byte[] message, ECPoint token, ECPoint precomputed) throws Exception {
        // Prepare command data: message + token + optional precomputed
        byte[] data = Util.concat(message, token.getEncoded(false));
        if (precomputed != null) {
            data = Util.concat(data, precomputed.getEncoded(false));
        }

        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_REDEEM_SINGLE,
                (byte) (precomputed == null ? 0 : 1),  // P1: precomputed flag
                (byte) 0,                              // P2: denomination
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
        
        // Redemption returns no data (just success/failure)
        Assertions.assertArrayEquals(new byte[0], responseAPDU.getData());
        return true;
    }

    /**
     * No-operation command for testing and benchmarking.
     * Does nothing but can be used to measure baseline communication overhead.
     */
    public void nop(byte[] data) throws Exception {
        nop(data, 0);
    }

    /**
     * No-operation command with configurable output size.
     * Used for performance testing with different data sizes.
     * 
     * @param data Input data to send (ignored by card)
     * @param outputSize Size of output data to return
     */
    public void nop(byte[] data, int outputSize) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_NOP,
                (byte) (outputSize & 0xff),  // P1: output size
                (byte) 0,                    // P2: unused
                data                         // Input data (ignored)
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
    }

    /**
     * Computes a zero-knowledge proof of knowledge of a secret.
     * Uses Schnorr signature scheme to prove knowledge of secret without revealing it.
     * This is the client-side implementation for simulating other parties' proofs.
     * 
     * @param secret The secret value to prove knowledge of
     * @param hashedPoint The hashed message point
     * @return Zero-knowledge proof (verifying_point || e || s)
     */
    public static byte[] computeProof(BigInteger secret, ECPoint hashedPoint) throws Exception {
        // Compute the verifying point (what we're proving we know the secret for)
        ECPoint verifyingPoint = hashedPoint.multiply(secret);

        // Generate random nonce for proof
        BigInteger r = randomBigInt(32);

        // Compute commitment points
        ECPoint A = hashedPoint.multiply(r);      // A = r * hashedPoint
        ECPoint B = ecSpec.getG().multiply(r);    // B = r * G

        // Create challenge hash (Fiat-Shamir transform)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(hashedPoint.getEncoded(false));                    // X
        md.update(verifyingPoint.getEncoded(false));                 // Y
        md.update(ecSpec.getG().getEncoded(false));                  // P (generator)
        md.update(ecSpec.getG().multiply(secret).getEncoded(false)); // Q (public key)
        md.update(A.getEncoded(false));                              // A
        md.update(B.getEncoded(false));                              // B

        // Compute challenge and response
        BigInteger e = new BigInteger(1, md.digest());               // Challenge
        BigInteger s = e.multiply(secret).add(r).mod(ecSpec.getN()); // Response
        
        // Construct proof: verifying_point || e || s
        byte[] proof = Util.concat(verifyingPoint.getEncoded(false), encodeBigInteger(e), encodeBigInteger(s));

        // Self-verify the proof
        Assertions.assertTrue(verifyProof(hashedPoint, ecSpec.getG().multiply(secret), proof));
        return proof;
    }

    /**
     * Verifies a zero-knowledge proof of knowledge.
     * Checks that the prover knows the secret corresponding to the partial mint key.
     * 
     * @param hashedPoint The hashed message point
     * @param partialMintKey The public key (G * secret)
     * @param proof The zero-knowledge proof to verify
     * @return true if proof is valid, false otherwise
     */
    public static boolean verifyProof(ECPoint hashedPoint, ECPoint partialMintKey, byte[] proof) throws Exception {
        // Extract proof components
        ECPoint verifyingPoint = ecSpec.getCurve().decodePoint(Arrays.copyOfRange(proof, 0, 65));      // Y
        BigInteger e = new BigInteger(1, Arrays.copyOfRange(proof, 65, 65 + 32));                      // e (challenge)
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(proof, 65 + 32, 65 + 32 + 32));           // s (response)

        // Recompute commitment points
        ECPoint A = hashedPoint.multiply(s).subtract(verifyingPoint.multiply(e));     // A = s*X - e*Y
        ECPoint B = ecSpec.getG().multiply(s).subtract(partialMintKey.multiply(e));   // B = s*G - e*Q

        // Recompute challenge hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(hashedPoint.getEncoded(false));        // X
        md.update(verifyingPoint.getEncoded(false));     // Y
        md.update(ecSpec.getG().getEncoded(false));      // P (generator)
        md.update(partialMintKey.getEncoded(false));     // Q (public key)
        md.update(A.getEncoded(false));                  // A
        md.update(B.getEncoded(false));                  // B
        
        BigInteger result = new BigInteger(1, md.digest());
        
        // Proof is valid if recomputed challenge matches original
        return e.equals(result);
    }

    /**
     * Hash-to-curve implementation (client-side reference).
     * Default to maximum 256 iterations for finding valid point.
     */
    public static ECPoint h2c(byte[] input) throws Exception {
        return h2c(input, 256);
    }

    /**
     * Hash-to-curve implementation with configurable iteration limit.
     * Converts arbitrary byte data to a valid elliptic curve point.
     * Uses try-and-increment method with domain separation.
     * 
     * @param input The input data to hash
     * @param maxIters Maximum iterations to try finding a valid point
     * @return A valid point on the elliptic curve
     */
    public static ECPoint h2c(byte[] input, int maxIters) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        
        // Domain separation to prevent cross-protocol attacks
        md.update(Consts.H2C_DOMAIN_SEPARATOR);
        md.update(input);
        byte[] prefix = md.digest();
        byte[] counter = new byte[4];

        // Try-and-increment method
        for (short i = 0; ; ++i) {
            md.reset();
            md.update(prefix);
            counter[0] = (byte) (i & 0xff);  // Add counter to get different x values
            md.update(counter);
            byte[] x = md.digest();
            
            try {
                // Try to create point with compressed format (0x02 prefix)
                return ecSpec.getCurve().decodePoint(Util.concat(new byte[]{0x02}, x));
            } catch (IllegalArgumentException e) {
                // x doesn't correspond to a valid point, try next iteration
                if (i + 1 >= maxIters)
                    throw e;  // Give up after maxIters attempts
            }
        }
    }

    /**
     * Generates a random BigInteger with specified byte length.
     * Used for generating cryptographic secrets and nonces.
     * 
     * @param bytes Number of bytes (will be converted to bits * 8)
     * @return Random BigInteger
     */
    public static BigInteger randomBigInt(int bytes) {
        return new BigInteger(bytes * 8, rnd);
    }

    /**
     * Encodes a BigInteger to exactly 32 bytes with leading zeros if needed.
     * Ensures consistent representation for cryptographic operations.
     * 
     * @param x The BigInteger to encode
     * @return 32-byte representation
     */
    public static byte[] encodeBigInteger(BigInteger x) {
        byte[] encoded = Util.trimLeadingZeroes(x.toByteArray());
        assert encoded.length <= 32;
        
        // Pad with leading zeros to get exactly 32 bytes
        while (encoded.length != 32) {
            encoded = Util.concat(new byte[1], encoded);
        }
        return encoded;
    }

    /**
     * Generates a random message that can be hashed to curve.
     * For performance testing - can generate messages that hash quickly or slowly.
     * 
     * @param precomputable If true, generates message that hashes in 1 iteration
     * @return Random message bytes
     */
    public static byte[] randomMessage(boolean precomputable) {
        byte[] message;
        boolean found = false;
        do {
            message = encodeBigInteger(randomBigInt(32));
            try {
                // Try hashing with limited iterations
                h2c(message, precomputable ? 1 : 256);
                found = true;
            } catch (Exception ignored) {
                // Message didn't hash successfully, try another
            }
        } while (!found);

        return message;
    }

    /**
     * Generates a random message that requires exactly 'repeats' iterations to hash.
     * Used for performance testing hash-to-curve iteration behavior.
     * 
     * @param repeats Exact number of iterations required
     * @return Random message bytes
     */
    public static byte[] randomMessage(int repeats) {
        byte[] message;
        boolean found = false;
        do {
            message = encodeBigInteger(randomBigInt(32));
            try {
                // Check that it takes exactly 'repeats' iterations
                h2c(message, repeats);
                if (repeats > 1) {
                    try {
                        // Should fail with one fewer iteration
                        h2c(message, repeats - 1);
                    } catch (Exception ignored) {
                        found = true;  // Perfect! Takes exactly 'repeats' iterations
                    }
                } else {
                    found = true;  // Takes 1 iteration
                }
            } catch (Exception ignored) {
                // Takes more than 'repeats' iterations, try another
            }
        } while (!found);

        return message;
    }
}
