package org.libsodium.jni.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.libsodium.jni.Sodium;

public class VRFTest {

    @Before
    public void setup() {
        Sodium.sodium_init();
    }

    @Test
    public void testCrypto_vrf_publickeybytes() {
        assertEquals( 32, Sodium.crypto_vrf_publickeybytes());
    }

    @Test
    public void testCrypto_vrf_secretkeybytes() {
        assertEquals( 64, Sodium.crypto_vrf_secretkeybytes());
    }

    @Test
    public void testCrypto_vrf_seedbytes() {
        assertEquals( 32, Sodium.crypto_vrf_seedbytes());
    }

    @Test
    public void testCrypto_vrf_proofbytes() {
        assertEquals( 80, Sodium.crypto_vrf_proofbytes());
    }

    @Test
    public void testCrypto_vrf_outputbytes() {
        assertEquals( 64, Sodium.crypto_vrf_outputbytes());
    }

    @Test
    public void testCrypto_vrf_keypair() {
        byte[] sk = new byte[Sodium.crypto_vrf_secretkeybytes()];
        byte[] pk = new byte[Sodium.crypto_vrf_publickeybytes()];
        byte[] seed = new byte[Sodium.crypto_vrf_seedbytes()];
        Sodium.crypto_vrf_keypair_from_seed(pk, sk, seed);

        assertEquals(1, Sodium.crypto_vrf_is_valid_key(pk));

        byte[] convertPk = new byte[Sodium.crypto_vrf_publickeybytes()];
        Sodium.crypto_vrf_sk_to_pk(convertPk ,sk);
        assertArrayEquals(pk, convertPk);

        byte[] convertSeed = new byte[Sodium.crypto_vrf_seedbytes()];
        Sodium.crypto_vrf_sk_to_seed(convertSeed ,sk);
        assertArrayEquals(seed, convertSeed);
    }

    @Test
    public void testCrypto_vrf_prove() {
        byte[] sk = new byte[Sodium.crypto_vrf_secretkeybytes()];
        byte[] pk = new byte[Sodium.crypto_vrf_publickeybytes()];
        byte[] proof = new byte[Sodium.crypto_vrf_proofbytes()];

        byte[] msg = "testVrf".getBytes();
        Sodium.crypto_vrf_keypair(pk, sk);
        Sodium.crypto_vrf_prove(proof, sk, msg, msg.length);

        byte[] hash = new byte[Sodium.crypto_vrf_outputbytes()];
        Sodium.crypto_vrf_proof_to_hash(hash, proof);

        assertEquals(0, Sodium.crypto_vrf_verify(hash, pk, proof, msg, msg.length));
    }
}
