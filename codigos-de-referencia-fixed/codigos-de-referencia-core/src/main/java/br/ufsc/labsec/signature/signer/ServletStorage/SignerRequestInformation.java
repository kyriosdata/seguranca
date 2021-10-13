package br.ufsc.labsec.signature.signer.ServletStorage;

import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;

import java.io.IOException;
import java.io.InputStream;

public interface SignerRequestInformation {

    InputStream getFileToBeSigned() throws IOException ;
    String getCertificatePassword();
    String getXmlUrl();
    SignerType getSignaturePolicy();
    FileFormat getSignatureFormat();
    String getSignatureSuite();
    String getPdfReason();
    String getPdfLocation();
    String getFilename();
}
