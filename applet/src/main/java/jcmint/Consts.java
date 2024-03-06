package jcmint;

public class Consts {
    public final static byte MAX_PARTIES = 3;

    public static final byte CLA_JCMINT = (byte) 0x00;

    public static final byte INS_SETUP = (byte) 0x00;
    public static final byte INS_ISSUE = (byte) 0x01;

    public final static short E_ALREADY_INITIALIZED = (short) 0xee00;
    public final static short E_INVALID_PARTY_COUNT = (short) 0xee01;

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
