# JCMint

JCMint is a JavaCard implementation of BDHKE and dBDHKE protocols on secp256k1 curve.

## Building the Applet

To build the applet, clone this repository with submodules, set your card type in [the main applet](applet/src/main/java/jcmint/JCMint.java#L10) file on [line 10](applet/src/main/java/jcmint/JCMint.java#L10), and run:

```
./gradlew buildJavaCard
```

The resulting cap file can be found in `applet/build/javacard/jcmint.cap`.

## Testing and performance measurement

Tests and performance measurement can be run using the following command. If you followed the instructions in the [Building the Applet](#building-the-applet) section, installed the applet on a card, and have it connected, you may change the [line 17](applet/src/test/java/tests/AppletTest.java#L17) in file [AppletTest.java](applet/src/test/java/tests/AppletTest.java#L17) and [line 17](applet/src/test/java/tests/PerformanceTest.java#L17) in file [PerformanceTest.java](applet/src/test/java/tests/PerformanceTest.java#L17) to run the tests on the smartcard; otherwise, the tests will run in a simulator.

```
./gradlew test
```

If you have multiple readers, you may have to select a different index in the [BaseText.java](applet/src/test/java/tests/BaseTest.java#L70) file.