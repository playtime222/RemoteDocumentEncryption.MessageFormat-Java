package nl.rijksoverheid.rdw.rde;

import nl.rijksoverheid.rdw.rde.messaging.zipV2.ZipMessageDecoder;
import org.bouncycastle.util.encoders.Hex;
;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


//Decode cross-platform messages
public class Step7_DecodeMessage
{
    @Test
    public void testN1() throws GeneralSecurityException, IOException { test("N 1"); }
    @Test
    public void testN2() throws GeneralSecurityException, IOException { test("N 2"); }
    @Test
    public void testN3() throws GeneralSecurityException, IOException { test("N 3"); }
    @Test
    public void testNW1() throws GeneralSecurityException, IOException
    {
        var tc = TestCases.Items.get("NW 1");
        // var f = new FileOutputStream("D:\\Message.zip");
        // f.write(Hex.decode(tc.EncodedMessage));
        // f.close();

        var secretKey = new SecretKeySpec(Hex.decode(tc.MessageEncryptionKey), "AES");
        var decoder = new ZipMessageDecoder();
        var actualRdeSessionArgs = decoder.decodeRdeSessionArgs(Hex.decode(tc.EncodedMessage));
        Assert.assertEquals(16, Hex.decode(actualRdeSessionArgs.getIv()).length);
        var message = decoder.decode(secretKey);
    }

    private static void test(final String name) throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
    {
        var tc = TestCases.Items.get(name);
        System.out.println("Secret Key: " + tc.MessageEncryptionKey) ;
        System.out.println("Message: " + tc.EncodedMessage) ;
        test(tc.MessageEncryptionKey, tc.EncodedMessage);
    }

    public static void test(final String secretKeyHex, final String messageHex) throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
    {
        var secretKey = new SecretKeySpec(Hex.decode(secretKeyHex), "AES");
        var decoder = new ZipMessageDecoder();
        var actualRdeSessionArgs = decoder.decodeRdeSessionArgs(Hex.decode(messageHex));
        Assert.assertEquals(16, Hex.decode(actualRdeSessionArgs.getIv()).length);
        var message = decoder.decode(secretKey);
        Assert.assertEquals("note", message.getNote());
        Assert.assertEquals("argle", message.getFiles()[0].getFilename());
        Assert.assertEquals("argle...", new String(message.getFiles()[0].getContent()));
    }
}