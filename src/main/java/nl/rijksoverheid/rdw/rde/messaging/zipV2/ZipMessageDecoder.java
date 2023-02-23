package nl.rijksoverheid.rdw.rde.messaging.zipV2;

import com.google.gson.Gson;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Locale;
import java.util.zip.ZipInputStream;

import nl.rijksoverheid.rdw.rde.messaging.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

//@Service
public class ZipMessageDecoder
{
    private String version;
    private MessageCipherInfo messageCipherInfo;
    private final Gson gson = new Gson();
    private Cipher messageCipher;
    private byte[] message;
    private String rdeSessionArgsJson;

    private final ArrayList<MessageFile> files = new ArrayList<>();
    private SecretKey secretKey;
    private byte[] iv;

    public MessageCipherInfo decodeRdeSessionArgs(final byte[] message) throws IOException
    {
        if (this.message != null) throw new IllegalStateException();
        this.message = message;

        this.version = readPlainTextString(ZipMessageEncoder.VersionEntryName);
        if (!version.equals(ZipMessageEncoder.Version))
            throw new IllegalArgumentException("Version not supported.");

        this.rdeSessionArgsJson = readPlainTextString(ZipMessageEncoder.RdeSessionArgsEntryName);
        this.messageCipherInfo = gson.fromJson(rdeSessionArgsJson, MessageCipherInfo.class);
        iv = Hex.decode(messageCipherInfo.getIv());
        return messageCipherInfo;
    }

    public MessageV2 decode(final SecretKey secretKey)
            throws IOException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        if (this.message == null) throw new IllegalStateException();
        if (this.messageCipher != null) throw new IllegalStateException();

        this.secretKey = secretKey;

        messageCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        messageCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        verifyPlainTextString(this.version, ZipMessageEncoder.VersionGmacEntryName);
        verifyPlainTextString(this.rdeSessionArgsJson, ZipMessageEncoder.RdeSessionArgsGmacEntryName);
        final var note = readPlainTextString(ZipMessageEncoder.NoteEntryName);
        verifyPlainTextString(note, ZipMessageEncoder.NoteGmacEntryName);

        final var metadataJsonBytes = readAndVerify(ZipMessageEncoder.MetadataEntryName, ZipMessageEncoder.MetadataGmacEntryName);
        final var json = new String(metadataJsonBytes, StandardCharsets.UTF_8);
        final var metadata = gson.fromJson(json, Metadata.class);

        for (var i = 0; i < metadata.getFilenames().length; i++)
        {
            var entryName = nextEntryName();
            files.add(new MessageFile(metadata.getFilenames()[i], readAndVerify(entryName, gmacEntryName())));
        }

        return new MessageV2(note, messageCipherInfo, files.toArray(new MessageFile[0]));
    }

    private byte[] readAndVerify(final String entryName, final String gmacEntryName) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        final var cipherText = readEntry(entryName);
        final var result = this.messageCipher.doFinal(cipherText);
        verify(result, gmacEntryName);
        return result;
    }

    private int fileCounter = 4; //-> First one is R_5_1
    private String nextEntryName() {fileCounter++; return String.format(Locale.ROOT, "R_%d_1", fileCounter); }
    private String gmacEntryName() {return String.format(Locale.ROOT, "AT_%d", fileCounter);}

    private String readPlainTextString(final String entryName) throws IOException {
        return new String(readEntry(entryName), StandardCharsets.UTF_8);
    }

    private void verifyPlainTextString(final String value, final String entryName) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        verify(value.getBytes(StandardCharsets.UTF_8), entryName);
    }

    private void verify(final byte[] value, final String gmacEntryName) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final var gmac = readEntry(gmacEntryName);
        final var decryptCipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
        decryptCipher.init(Cipher.DECRYPT_MODE, this.secretKey, new GCMParameterSpec(iv.length * 8, iv), new SecureRandom());
        decryptCipher.updateAAD(value);
        decryptCipher.update(gmac);
        decryptCipher.doFinal(); //Throws if bad gmac
    }

    private byte[] readEntry(final String name) throws IOException
    {
        try(final var input = new ByteArrayInputStream(this.message))
        {
            try(final var stream = new ZipInputStream(input))
            {
                var zipEntry = stream.getNextEntry();
                while (zipEntry != null)
                {
                    if (zipEntry.getName().equals(name))
                    {
                        final var buffer = new byte[2048];
                        final var result = new ByteArrayOutputStream();
                        int len = stream.read(buffer);
                        while (len > 0)
                        {
                            result.write(buffer, 0, len);
                            len = stream.read(buffer);
                        }
                        return result.toByteArray();
                    }
                    zipEntry = stream.getNextEntry();
                }
                throw new IllegalStateException("Entry not found.");
            }
        }
    }
}