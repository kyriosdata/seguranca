package br.ufsc.labsec.signature.conformanceVerifier.xml;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.List;

import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.RevocationInformation;

/**
 * Esta classe gerencia as listas de certificados e CRLs de uma assinatura XML.
 * Implementa {@link RevocationInformation} e {@link CertificateCollection}.
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
public class SignatureIdentityInformation implements RevocationInformation, CertificateCollection {
    /**
     * Lista de certificados usados na assinatura
     */
    private List<X509Certificate> certificates;
    /**
     * Lista de Certificados Revogados
     */
    private List<X509CRL> crls;
    /**
     * Componente de assinatura XML
     */
    private XmlSignatureComponent xmlSignatureComponent;

    /**
     *  Construtor da classe
     * @param XmlSignatureComponent Um componente de assinatura XML
     */
    public SignatureIdentityInformation(XmlSignatureComponent XmlSignatureComponent) {
        this.certificates = new ArrayList<X509Certificate>();
        this.crls = new ArrayList<X509CRL>();
        this.xmlSignatureComponent = XmlSignatureComponent;
    }

    /**
     * Busca por um certificado entre a lista de certificados da assinatura
     * @param certSelector Selector para identificar o certificado desejado
     * @return O certificado desejado, ou nulo caso não seja encontrado
     */
    @Override
    public Certificate getCertificate(CertSelector certSelector) {
        for (Certificate certificate : this.getCertificateList()) {
            if (certSelector.match(certificate)) {
                return certificate;
            }
        }
        return null;
    }

    /**
     * Adiciona os certificados à lista de certificados da assinatura
     * @param certificates Lista de certificados a serem adicionados
     */
    @Override
    public void addCertificates(List<X509Certificate> certificates) {

        for (X509Certificate cert : certificates) {
            if (!this.certificates.contains(cert)) {
                this.certificates.add(cert);
            }
        }
    }

    /**
     * Busca a CRL de um certificado
     * @param certificate Certificado que se deseja a CRL
     * @param timeReference Data da CRL desejada
     * @return A CRL desejada, ou nulo caso não seja encontrada
     */
    @Override
    public CRLResult getCRLFromCertificate(Certificate certificate, Time timeReference) {

        for (X509CRL x509crl : this.crls) {
            X509Certificate xCert = (X509Certificate) certificate;
            if (xCert.getIssuerX500Principal().equals(x509crl.getIssuerX500Principal())) {
                if (x509crl.getThisUpdate().compareTo(timeReference) >= 0
                        && x509crl.getNextUpdate().compareTo(timeReference) < 0) {
                    CRLResult result = new CRLResult();
                    result.crl = x509crl;
                    result.fromWeb = false;
                    return result;
                }
            }
        }

        return null;
    }

    /**
     * Retorna a lista de certificados utilizados na assinatura
     * @return Lista de certificados da assinatura
     */
    @Override
    public List<Certificate> getCertificateList() {

        XmlSignature xmlSignature = xmlSignatureComponent.getVerifier().getSelectedSignature();
        if (xmlSignature != null) {
            List<X509Certificate> xmlCertlist = null;
            List<Certificate> certList = new ArrayList<Certificate>();

            xmlCertlist = xmlSignature.getCertificatesAtKeyInfo();

            for (X509Certificate x509Certificate : xmlCertlist) {
                if (!certList.contains(x509Certificate)) {
                    certList.add((Certificate) x509Certificate);
                }
            }

            for (X509Certificate certificate : this.certificates) {
                if (!certList.contains(certificate)) {
                    certList.add(certificate);
                }
            }
            return certList;
        } else {
            List<Certificate> certs = new ArrayList<Certificate>(this.certificates);
            return certs;
        }
    }

    @Override
    public X509Certificate getIssuerCertificate(X509Certificate certificate) {
        return null;
    }

    /**
     * Adiciona uma CRL à lista de certificados revogados
     * @param certValuesCertificates Lista de certificados aos quais pertencem as CRLs
     * @param crlsList A lista de CRLs a ser adicionada
     */
    @Override
    public void addCrl(List<X509Certificate> certValuesCertificates, List<X509CRL> crlsList) {
        this.crls.addAll(crlsList);
    }
}
