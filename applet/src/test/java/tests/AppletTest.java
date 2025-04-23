package tests;

import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.ISO7816;
import jcmint.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;

/**
 * Test suite for the JCMint smart card applet.
 * Tests core cryptographic minting functionality including setup, issuance, verification,
 * swap operations, and redemption for digital coins/tokens.
 */
public class AppletTest extends BaseTest {
    // Index of this card/mint in a multi-party setup (0-indexed)
    private final byte CARD_IDX = 0;
    
    public AppletTest() {
        // Use local JavaCard simulator for testing
        setCardType(CardType.JCARDSIMLOCAL);
        // Don't simulate stateful connections (fresh connection each test)
        setSimulateStateful(false);
    }


    /**
     * Tests the setup phase for multi-party minting.
     * This initializes the cryptographic keys for all participating mints.
     */
    @Test
    public void testSetup() throws Exception {
        // Initialize secrets of all mints for different party configurations
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        // Test setup with 1 to MAX_PARTIES participants
        for (int parties = 1; parties <= Consts.MAX_PARTIES; ++parties) {
            BigInteger[] secrets = new BigInteger[parties];
            // Setup will generate random secrets and compute the combined mint public key
            pm.setup(secrets);
        }
    }

    /**
     * Tests the token issuance functionality.
     * In the issuance phase, a client provides a challenge point and receives
     * a partial signature from this mint.
     */
    @Test
    public void testIssue() throws Exception {
        // Test issuance with different numbers of parties
        for(int i = 1; i <= Consts.MAX_PARTIES; ++i) {
            // Skip if this card index is not valid for current party count
            if (CARD_IDX >= i) {
                continue;
            }
            ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
            BigInteger[] secrets = new BigInteger[i];
            pm.setup(secrets);

            // Create a random challenge point (client's blinded message)
            BigInteger scalar = ProtocolManager.randomBigInt(32);
            ECPoint challenge = ProtocolManager.G.multiply(scalar);
            
            // Issue partial signature from this mint
            ECPoint output = pm.issue(challenge);
            
            // Verify the output is challenge * this_mint_secret
            Assertions.assertArrayEquals(challenge.multiply(secrets[CARD_IDX]).getEncoded(false), output.getEncoded(false));
        }
    }

    /**
     * Tests the hash-to-curve functionality.
     * This converts arbitrary byte data into valid elliptic curve points,
     * used for deterministic point generation from secrets.
     */
    @Test
    public void testHashToCurve() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        
        // Test with all zeros (32-byte array)
        byte[] data = new byte[32];
        Assertions.assertArrayEquals(Util.hexStringToByteArray("044cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a72532e97a708760bfdc863bc2731ce604c7b7cb9df2a55410f18ce031fc1dcfb18e"), pm.hashToCurve(data).getEncoded(false));
        
        // Test with data ending in 0x01
        data[31] = 0x01;
        Assertions.assertArrayEquals(Util.hexStringToByteArray("042e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf7b22eee931599a72e1df1628c605c47a9f282944e97f67ba52f79e2a18ac77f8"), pm.hashToCurve(data).getEncoded(false));
        
        // Test with data ending in 0x02
        data[31] = 0x02;
        Assertions.assertArrayEquals(Util.hexStringToByteArray("046cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f7231a9756caa84811bfe53cb35b626fc0faa43ccd436d07369813b55831584ac"), pm.hashToCurve(data).getEncoded(false));
    }

    /**
     * Tests error handling for unknown APDU instructions.
     * Verifies the applet properly rejects unrecognized commands.
     */
    @Test
    public void testUnknownInstruction() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        // Send APDU with invalid instruction byte (0x12)
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,    // Correct class byte
                (byte) 0x12,          // Invalid instruction
                (byte) 0x34,          // P1 parameter
                (byte) 0x56,          // P2 parameter
                new byte[0]           // No data
        );
        ResponseAPDU responseAPDU = pm.cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        // Should return "instruction not supported" error
        Assertions.assertEquals(responseAPDU.getSW(), ISO7816.SW_INS_NOT_SUPPORTED);
    }

    /**
     * Tests double-spending prevention in the verification process.
     * Ensures that once a token is verified/spent, it cannot be used again.
     */
    @Test
    public void testVerifyFail() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        pm.setup(new BigInteger[1]);

        // First verification should succeed
        pm.verify(new byte[32], ProtocolManager.G, null);
        
        // Try to verify the same message+token again - should fail
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCMINT,
                Consts.INS_VERIFY,
                (byte) 0,   // No precomputed hash
                (byte) 0,   // Denomination 0
                Util.concat(new byte[32], ProtocolManager.G.getEncoded(false))
        );
        ResponseAPDU responseAPDU = pm.cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        // Should return "already spent" error
        Assertions.assertEquals(Consts.E_ALREADY_SPENT & 0xffff, responseAPDU.getSW());
    }

    /**
     * Tests the cryptographic proof verification process.
     * Verifies that the zero-knowledge proof generated by the card is valid.
     */
    @Test
    public void testVerifyProof() throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        ECPoint mintKey = pm.setup(new BigInteger[1]);
        
        // Create a secret and hash it to a curve point
        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        
        // Generate a zero-knowledge proof of knowledge of the secret
        byte[] proof = pm.verify(new byte[32], ProtocolManager.G, null);

        // Verify the proof is cryptographically valid
        Assertions.assertTrue(ProtocolManager.verifyProof(hashedPoint, mintKey, proof));
    }

    /**
     * Tests the token swap functionality for multi-party scenarios.
     * Tests both with and without precomputed hash values for optimization.
     */
    @Test
    public void testSwap() throws Exception {
        for (int i = 1; i <= Consts.MAX_PARTIES; ++i) {
            // Test swap without precomputed hash (slower but more flexible)
            verifySwap(false, i);
            // Test swap with precomputed hash (faster if hash is known)
            verifySwap(true, i);
        }
    }

    /**
     * Verifies the token swap operation for multi-party minting.
     * A swap exchanges an old token for a new one with a different challenge point.
     * 
     * @param precomputed Whether to use precomputed hash-to-curve value
     * @param parties Number of participating mints
     */
    public void verifySwap(boolean precomputed, int parties) throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        BigInteger[] privateKeys = new BigInteger[parties];
        pm.setup(privateKeys);
        
        // Create a secret and generate the corresponding token
        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        
        // Get partial signature from this mint
        ECPoint token = pm.issue(hashedPoint);
        
        // Simulate signatures from other mints to create full token
        for (int i = 0; i < parties; ++i) {
            if (i == CARD_IDX) {
                continue;  // Skip our own signature (already included)
            }
            token = token.add(hashedPoint.multiply(privateKeys[i]));
        }

        // Collect zero-knowledge proofs from all parties
        byte[] proofs = new byte[0];
        for (int i = 0; i < parties; ++i) {
            if (i == CARD_IDX) {
                // Get proof from the smart card
                proofs = Util.concat(proofs, pm.verify(secret, token, precomputed ? hashedPoint : null));
            } else {
                // Simulate proofs from other parties
                proofs = Util.concat(proofs, ProtocolManager.computeProof(privateKeys[i], hashedPoint));
            }
        }
        
        // Perform the swap: exchange old token for new one with different challenge
        ECPoint newToken = pm.swap(secret, token, ProtocolManager.G, proofs);
        
        // New token should be G * this_mint_secret
        Assertions.assertArrayEquals(ProtocolManager.G.multiply(privateKeys[CARD_IDX]).getEncoded(false), newToken.getEncoded(false));
    }

    /**
     * Tests token swap for single-party (non-federated) scenarios.
     * Simpler case where only one mint is involved.
     */
    @Test
    public void testSwapSingle() throws Exception {
        swapSingle(false);  // Without precomputed hash
        swapSingle(true);   // With precomputed hash
    }

    /**
     * Tests the token redemption functionality for multi-party scenarios.
     * Redemption destroys a token and proves it was valid.
     */
    @Test
    public void testRedeem() throws Exception {
        for (int i = 1; i <= Consts.MAX_PARTIES; ++i) {
            verifyRedeem(false, i);  // Without precomputed hash
            verifyRedeem(true, i);   // With precomputed hash
        }
    }

    /**
     * Verifies the token redemption operation for multi-party minting.
     * Redemption proves ownership of a valid token and marks it as spent.
     * 
     * @param precomputed Whether to use precomputed hash-to-curve value
     * @param parties Number of participating mints
     */
    public void verifyRedeem(boolean precomputed, int parties) throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        BigInteger[] privateKeys = new BigInteger[parties];
        pm.setup(privateKeys);

        // Create a secret and generate the corresponding token
        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        
        // Get partial signature from this mint
        ECPoint token = pm.issue(hashedPoint);
        
        // Simulate signatures from other mints to create full token
        for (int i = 0; i < parties; ++i) {
            if (i == CARD_IDX) {
                continue;  // Skip our own signature (already included)
            }
            token = token.add(hashedPoint.multiply(privateKeys[i]));
        }

        // Collect zero-knowledge proofs from all parties
        byte[] proofs = new byte[0];
        for (int i = 0; i < parties; ++i) {
            if (i == CARD_IDX) {
                // Get proof from the smart card
                proofs = Util.concat(proofs, pm.verify(secret, token, precomputed ? hashedPoint : null));
            } else {
                // Simulate proofs from other parties
                proofs = Util.concat(proofs, ProtocolManager.computeProof(privateKeys[i], hashedPoint));
            }
        }
        
        // Redeem the token (marks it as spent)
        Assertions.assertTrue(pm.redeem(secret, token, proofs));
    }

    /**
     * Verifies token swap for single-party (non-federated) scenarios.
     * 
     * @param precomputed Whether to use precomputed hash-to-curve value
     */
    public void swapSingle(boolean precomputed) throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        ECPoint mintKey = pm.setup(new BigInteger[1]);

        // Create a secret and generate the corresponding token
        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        ECPoint token = pm.issue(hashedPoint);

        // Swap for a new token with challenge point G
        ECPoint newToken = pm.swapSingle(secret, token, ProtocolManager.G, precomputed ? hashedPoint : null);
        
        // New token should equal the mint's public key
        Assertions.assertArrayEquals(mintKey.getEncoded(false), newToken.getEncoded(false));
    }

    /**
     * Tests token redemption for single-party (non-federated) scenarios.
     */
    @Test
    public void testRedeemSingle() throws Exception {
        redeemSingle(false);  // Without precomputed hash
        redeemSingle(true);   // With precomputed hash
    }

    /**
     * Verifies token redemption for single-party (non-federated) scenarios.
     * 
     * @param precomputed Whether to use precomputed hash-to-curve value
     */
    public void redeemSingle(boolean precomputed) throws Exception {
        ProtocolManager pm = new ProtocolManager(connect(), CARD_IDX);
        ECPoint mintKey = pm.setup(new BigInteger[1]);

        // Create a secret and generate the corresponding token
        byte[] secret = new byte[32];
        ECPoint hashedPoint = pm.hashToCurve(secret);
        ECPoint token = pm.issue(hashedPoint);

        // Redeem the token (single-party version)
        Assertions.assertTrue(pm.redeemSingle(secret, token, precomputed ? hashedPoint : null));
    }
}
