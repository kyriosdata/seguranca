package br.ufsc.labsec.signature.repository.PKCS12IdentityService;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import br.ufsc.labsec.component.Application;

//FIXME implementar
public class IcpBrasilCertificateChecker extends PKIXCertPathChecker {

    private List<String> individual; // pessoa física
    private List<String> corporate; // pessoa jurídica
    private List<String> aplication;
    private Set<String> noncritical;
    private Set<String> critical;

    public IcpBrasilCertificateChecker() {
        this.individual = new ArrayList<String>();
        this.aplication = new ArrayList<String>();
        this.corporate = new ArrayList<String>();
        this.critical = new HashSet<String>();
        this.noncritical = new HashSet<String>();
        this.individual.add("2.16.76.1.3.1");
        this.individual.add("2.16.76.1.3.6");
        this.individual.add("2.16.76.1.3.5");
        this.corporate.add("2.16.76.1.3.4");
        this.corporate.add("2.16.76.1.3.2");
        this.corporate.add("2.16.76.1.3.3");
        this.corporate.add("2.16.76.1.3.7");
        this.aplication.add("2.16.76.1.3.8");
        this.aplication.add("2.16.76.1.3.3");
        this.aplication.add("2.16.76.1.3.2");
        this.aplication.add("2.16.76.1.3.4");

        this.noncritical.add("2.5.29.14"); // Authority Key Identifier
        this.noncritical.add("2.5.29.32"); // Certificate Policies
        this.noncritical.add("2.5.29.31"); // CRL Distribution Points
        this.noncritical.add("1.3.6.1.5.5.7.1.1");// Authority Information
                                                  // Access

        this.critical.add("2.5.29.15"); // Key Usage
        this.critical.add("2.5.29.37");// Extended Key Usage
    }

    @Override
    public void init(boolean forward) throws CertPathValidatorException {

    }

    @Override
    public boolean isForwardCheckingSupported() {
        return false;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return null;
    }

    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        X509Certificate certificate = (X509Certificate) cert;
        byte[] extensionBytes = certificate.getExtensionValue("2.5.29.17");
        DEROctetString extensionSequence = null;

        try {
            extensionSequence = (DEROctetString) ASN1Sequence.fromByteArray(extensionBytes);
            ASN1Sequence sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(extensionSequence.getOctets());
            List<String> der = new ArrayList<String>();

            for (int i = 0; i < sequence.size(); i++) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) sequence.getObjectAt(i);
                if (tagged.getTagNo() == 0) {
                    ASN1Sequence derSequence = (ASN1Sequence) tagged.getObject();
                    ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier) derSequence.getObjectAt(0);
                    der.add(identifier.toString());
                }
            }

            Set<String> nonCriticalExtensions = certificate.getNonCriticalExtensionOIDs();
            Set<String> criticalExtension = certificate.getCriticalExtensionOIDs();
            if (!nonCriticalExtensions.equals(this.noncritical) && !criticalExtension.equals(this.critical)
                    && !equalLists(this.aplication, der) && !equalLists(this.individual, der) && !equalLists(this.corporate, der))
                throw new CertPathValidatorException("Certificado não é válido pelas regras da Icp Brasil.");

        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, "Não foi possível decodificar a extensão.", e);
        }
    }

    private boolean equalLists(List<String> cert, List<String> userCert) {
        if (cert.size() > userCert.size())
            return false;

        int t = 0;
        for (int i = 0; i < cert.size(); i++) {
            if (cert.get(i).compareTo(userCert.get(i)) == 0)
                t++;
        }
        return t == cert.size();
    }

}
