package nl.rijksoverheid.rdw.rde.messaging;

public class MessageV2 {
    private final String note;
    private final MessageCipherInfo rdeSessionArgs;
    private final MessageFile[] files;

    public MessageV2(final String note, final MessageCipherInfo rdeSessionArgs, final MessageFile[] objects) {

        this.note = note;
        this.rdeSessionArgs = rdeSessionArgs;
        this.files = objects;
    }

    public String getNote() {
        return note;
    }

    public MessageFile[] getFiles() {
        return files;
    }

    public MessageCipherInfo getRdeSessionArgs() {
        return rdeSessionArgs;
    }
}
