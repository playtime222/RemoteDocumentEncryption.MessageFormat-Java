package nl.rijksoverheid.rdw.rde.messaging;

public class MessageCipherInfo {

    //Hex-encoded 16 byte IV - set by the message encoder. TODO Could choose to do this as a separate step depending on the chosen cipher
    private String iv;
    private RdeMessageDecryptionInfo rdeInfo;

    public String getIv() {return iv;}

    public RdeMessageDecryptionInfo getRdeMessageDecryptionInfo() {return rdeInfo;}

    public void setIv(final String value) { iv = value; }
    public void setRdeInfo(final RdeMessageDecryptionInfo value) { rdeInfo = value; }
}
