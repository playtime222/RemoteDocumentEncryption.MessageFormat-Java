package nl.rijksoverheid.rdw.rde.messaging.zipV2;

//TODO add mimetypes etc.
public class Metadata {
    public String[] getFilenames() {
        return filenames;
    }

    public void setFilenames(final String[] filenames) {
        this.filenames = filenames;
    }

    private String[] filenames;
}
