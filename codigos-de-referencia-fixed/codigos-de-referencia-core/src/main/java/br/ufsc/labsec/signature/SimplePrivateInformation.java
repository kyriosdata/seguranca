package br.ufsc.labsec.signature;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Esta classe reúne informações do assinante.
 */
public class SimplePrivateInformation implements PrivateInformation {

    /**
     * Certificado do assinante
     */
    private final Certificate certificate;
    /**
     * Chave privada do assinante
     */
    private final PrivateKey privateKey;

    public SimplePrivateInformation(Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    @Override
    public X509Certificate getCertificate() {
        return (X509Certificate) this.certificate;
    }
}
