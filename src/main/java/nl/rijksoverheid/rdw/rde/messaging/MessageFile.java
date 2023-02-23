package nl.rijksoverheid.rdw.rde.messaging;

public class MessageFile {
    private final String filename;
    private final byte[] content;

    public MessageFile(final String filename, final byte[] content) {
        this.filename = filename;
        this.content = content;
    }

    public String getFilename() {
        return filename;
    }

    public byte[] getContent() {
        return content;
    }
}
