package nl.rijksoverheid.rdw.rde.messaging;

public class RdeMessageDecryptionInfo {
    /// <summary>
    /// Display name for the receiver's document used during enrolment
    /// </summary>
    private String documentDisplayName;

    /// <summary>
    /// From the DG14 info.
    /// </summary>
    private String caProtocolOid;

    /// <summary>
    /// Hex encoded
    /// AKA Ephemeral Key Z
    /// </summary>
    private String pcdPublicKey; //from EAC CA session

    /// <summary>
    /// Hex encoded
    /// Encrypted RB command
    /// </summary>
    private String command; //from EAC CA session

    public String getDocumentDisplayName() {return documentDisplayName;}
    public String getCaProtocolOid() {return caProtocolOid;}
    public String getPcdPublicKey() {return pcdPublicKey;}
    public String getCommand() {return command;}

    public void setDocumentDisplayName(final String value) { documentDisplayName = value;}
    public void setCaProtocolOid(final String value) { caProtocolOid = value;}
    public void setPcdPublicKey(final String value) { pcdPublicKey = value;}
    public void setCommand(final String value) { command = value;}
}
