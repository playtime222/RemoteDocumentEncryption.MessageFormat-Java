package nl.rijksoverheid.rdw.rde;

/// <summary>
/// All current tests based on DG14 from SPEC2014
/// </summary>
public class TestCase {
    public String PcdPrivateKey;
    public String PcdPublicKey;
    public String SharedSecret;
    public String KsEnc;
    public String KsMac;
    public int File = 14;
    public int Length;
    public String CommandApdu;
    public String WrappedCommandApdu;

    //AES of the first Length bytes of DG14
    public String EncryptedPaddedResponse;
    public String WrappedResponse;
    public String MessageEncryptionKey;
    public String EncodedMessage;
}
