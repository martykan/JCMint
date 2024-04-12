package jcmint;

public class Consts {
    public final static byte MAX_PARTIES = 5;
    public static final byte[] H2C_DOMAIN_SEPARATOR = {(byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x70, (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x6b, (byte) 0x31, (byte) 0x5f, (byte) 0x48, (byte) 0x61, (byte) 0x73, (byte) 0x68, (byte) 0x54, (byte) 0x6f, (byte) 0x43, (byte) 0x75, (byte) 0x72, (byte) 0x76, (byte) 0x65, (byte) 0x5f, (byte) 0x43, (byte) 0x61, (byte) 0x73, (byte) 0x68, (byte) 0x75, (byte) 0x5f};

    public static final byte CLA_JCMINT = (byte) 0x00;

    public static final byte INS_SETUP = (byte) 0x00;
    public static final byte INS_ISSUE = (byte) 0x01;
    public static final byte INS_HASH_TO_CURVE = (byte) 0x02;
    public static final byte INS_VERIFY = (byte) 0x03;
    public static final byte INS_SWAP = (byte) 0x04;
    public static final byte INS_SWAP_SINGLE = (byte) 0x05;
    public static final byte INS_REDEEM = (byte) 0x06;
    public static final byte INS_REDEEM_SINGLE = (byte) 0x07;
    public static final byte INS_NOP = (byte) 0x08;

    public final static short E_ALREADY_INITIALIZED = (short) 0xee00;
    public final static short E_INVALID_PARTY_COUNT = (short) 0xee01;
    public final static short E_ALREADY_SPENT = (short) 0xee02;
    public final static short E_NOT_VERIFYING = (short) 0xee03;
    public final static short E_VERIFICATION_FAILED_PROOF = (short) 0xee04;
    public final static short E_VERIFICATION_FAILED_TOKEN = (short) 0xee05;
    public final static short E_INVALID_PRECOMPUTE = (short) 0xee06;

    public final static short SW_Exception = (short) 0xff01;
    public final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    public final static short SW_ArithmeticException = (short) 0xff03;
    public final static short SW_ArrayStoreException = (short) 0xff04;
    public final static short SW_NullPointerException = (short) 0xff05;
    public final static short SW_NegativeArraySizeException = (short) 0xff06;
    public final static short SW_CryptoException_prefix = (short) 0xf100;
    public final static short SW_SystemException_prefix = (short) 0xf200;
    public final static short SW_PINException_prefix = (short) 0xf300;
    public final static short SW_TransactionException_prefix = (short) 0xf400;
    public final static short SW_CardRuntimeException_prefix = (short) 0xf500;
}
