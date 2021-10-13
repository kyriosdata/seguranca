package br.ufsc.labsec.signature;

import org.apache.commons.io.input.NullInputStream;

import java.io.InputStream;

public class SignatureDataWrapper {

    private InputStream signedData;
    private InputStream detachedData;
    private String filename;

    public SignatureDataWrapper(InputStream signedData, InputStream detachedData, String filename) {
        if (signedData == null) {
            throw new IllegalArgumentException("'signedData' cannot be null.");
        }
        this.signedData = signedData;
        this.detachedData = detachedData;
        this.filename = filename;
    }

    public void setDetachedData(InputStream detStream) {
        if (detachedData == null) return;
        detachedData = detStream;
    }

    public InputStream sig() {
        return signedData;
    }

    public InputStream det() {
        return (detachedData != null) ? detachedData : new NullInputStream(0);
    }

    public String name() {return filename;}

}
