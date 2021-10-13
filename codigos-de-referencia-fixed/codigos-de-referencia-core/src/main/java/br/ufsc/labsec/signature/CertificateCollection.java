package br.ufsc.labsec.signature;

import br.ufsc.labsec.signature.exceptions.CertificateCollectionException;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateCollection {

    Certificate getCertificate(CertSelector certSelector);
    
    List<Certificate> getCertificateList();

    X509Certificate getIssuerCertificate(X509Certificate certificate) throws CertificateCollectionException;

    public void addCertificates(List<X509Certificate> certificates);

    default public void addCertPath(List<X509Certificate> certPath) {
        this.addCertificates(certPath);
    }
}
