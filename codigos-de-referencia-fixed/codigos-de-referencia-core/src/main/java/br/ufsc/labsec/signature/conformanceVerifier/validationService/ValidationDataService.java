package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import br.ufsc.labsec.signature.conformanceVerifier.report.ValidationDataReport;
import br.ufsc.labsec.signature.exceptions.AIAException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Esta classe é responsável pela validação da AIA (Authority Information Access)
 * dos certificados digitais
 */
public class ValidationDataService {

    private static final String id_pe_authorityInfoAccess = "1.3.6.1.5.5.7.1.1";
    private static final String id_ad_caIssuers = "1.3.6.1.5.5.7.48.2";

    private static final String NO_AIA_AVAILABLE = "O certificado não contém " +
            "extensão AIA para importar o caminho de certificação.";
    private static final String INVALID_AIA_ENCODING = "Não foi possível " +
            "fazer a decodificação da extensão AIA do certificado ";
    private static final String CORRUPTED_CERT = "Um dos certificados indicados " +
            "pela extensão AIA do certificado a seguir está corrompido: ";
    private static final String NO_CERTS_IN_CHAIN = "Não foi possível " +
            "recuperar certificados do caminho de certificação";
    private static final String NO_ISSUER_MATCH = "Não foi possível obter o " +
            "emissor do certificado ";

    /**
     * Realiza o download da cadeia de certificação através da AIA do certificado
     * @param signerCert O certificado do qual será buscado a cadeia de certificação
     * @return Lista de certificados na ordem da cadeia de certificação do certificado
     * @throws AIAException exceção caso o certificado não possua AIA ou em caso de erro
     * na codificação do certificado
     */
    public static List<X509Certificate> downloadCertChainFromAia(X509Certificate signerCert) throws AIAException {

        assert signerCert != null;
        if (!signerCert.getNonCriticalExtensionOIDs().contains(id_pe_authorityInfoAccess)) {
            throw new AIAException(NO_AIA_AVAILABLE);
        }

        List<X509Certificate> certificates = new ArrayList<>();
        certificates.add(signerCert);
        certificates.addAll(downloadCertificationChainFromAia(signerCert));
        return orderCertList(certificates, signerCert);

    }

    /**
     * Gera um relatório de validação do certificado
     * @param subjectCert O certificado a ser verificado
     * @param issuerCert O certificado do emissor
     * @return Relatório com as informações da validação do certificado
     */
    public static ValidationDataReport getValidationData(X509Certificate subjectCert, X509Certificate issuerCert) {

        ValidationDataReport validationData = new ValidationDataReport();
        validationData.setCertificateOnline(false);
        boolean valid = true;

        try {
            subjectCert.verify(issuerCert.getPublicKey());
        } catch (Exception e) {
            valid = false;
        }

        validationData.setValidCertificate(valid);
        validationData.setCertificateIssuerName(subjectCert.getIssuerX500Principal().toString());
        validationData.setNotBefore(subjectCert.getNotBefore());
        validationData.setNotAfter(subjectCert.getNotAfter());
        validationData.setCertificateSubjectName(subjectCert.getSubjectX500Principal().toString());
        validationData.setCertificateSerialNumber(subjectCert.getSerialNumber().toString());

        return validationData;

    }

    /**
     * Realiza o download da cadeia de certificação através da AIA do certificado
     * @param cert O certificado do qual será buscado a cadeia de certificação
     * @return Lista de certificados pertencentes à cadeia de certificação do certificado
     * sem nenhuma ordem
     * @throws AIAException exceção em caso de erro na codificação do certificado
     */
    private static List<X509Certificate> downloadCertificationChainFromAia(X509Certificate cert) throws AIAException {

        AuthorityInformationAccess aia = loadAuthorityInformationAccess(cert);
        AccessDescription[] descriptions = aia.getAccessDescriptions();
        ASN1ObjectIdentifier httpMethod = new ASN1ObjectIdentifier(id_ad_caIssuers);
        List<X509Certificate> certificationChain = null;

        boolean downloaded = false;
        for (int i = 0; i < descriptions.length && !downloaded; ++i) {
            AccessDescription ad = descriptions[i];
            if (ad.getAccessMethod().equals(httpMethod)) {
                URL accessPoint;
                try {
                    accessPoint = new URL(ad.getAccessLocation().getName().toString());
                    certificationChain = downloadCertificateChain(accessPoint);
                    downloaded = true;
                } catch (CertificateException e) {
                    throw new AIAException(CORRUPTED_CERT + cert.getIssuerX500Principal().toString());
                } catch (IOException e) {
                    /*
                     * Se não for possível baixar de um lugar, talvez seja
                     * possível baixar de outro
                     */
                }
            }
        }

        if (certificationChain == null) {
            throw new AIAException(NO_CERTS_IN_CHAIN);
        }

        return new ArrayList<>(certificationChain);

    }

    /**
     * Gera uma AIA através da informação no certificado dado
     * @param cert O certificado do qual será carregada a AIA
     * @return A AIA do certificado
     * @throws AIAException exceção caso o certificado esteja com erro de codificação
     */
    private static AuthorityInformationAccess loadAuthorityInformationAccess(X509Certificate cert) throws AIAException {

        byte[] aiaBytes = cert.getExtensionValue(id_pe_authorityInfoAccess);
        ASN1OctetString aiaOctets;
        ASN1Sequence aiaSequence;

        try {
            aiaOctets = (ASN1OctetString) ASN1OctetString.fromByteArray(aiaBytes);
            aiaSequence = (ASN1Sequence) ASN1Sequence
                    .fromByteArray(aiaOctets.getOctets());
            return AuthorityInformationAccess.getInstance(aiaSequence);
        } catch (IOException | IllegalArgumentException e) {
            /*
             * Somente irá acontecer se o certificado estiver codificado errado,
             * o que é bem improvável
             */
            throw new AIAException(INVALID_AIA_ENCODING
                    + cert.getIssuerX500Principal().toString());
        }

    }

    /**
     * Realiza o download da cadeia de certificação disponível na URL
     * @param accessLocationUrl A URL onde será feito o download
     * @return Lista de certificados que pertencem à cadeia de certificação
     * @throws IOException exceção em caso de erro na conexão
     * @throws CertificateException exceção em caso de erro na conexão
     */
    private static List<X509Certificate> downloadCertificateChain(URL accessLocationUrl)
            throws IOException, CertificateException {

        List<X509Certificate> certs;
        HttpURLConnection connection = (HttpURLConnection) accessLocationUrl.openConnection();
        connection.setConnectTimeout(1000);
        int response = connection.getResponseCode();

        do {
            if (response == HttpURLConnection.HTTP_NOT_FOUND) {
                return new ArrayList<>();
            }
            if (response >= HttpURLConnection.HTTP_MULT_CHOICE && response <= HttpURLConnection.HTTP_SEE_OTHER) {
                String newUrl = connection.getHeaderField("Location");
                connection = (HttpURLConnection) new URL(newUrl).openConnection();
                connection.setConnectTimeout(1000);
                response = connection.getResponseCode();
            }
            if (response != HttpURLConnection.HTTP_OK) {
                throw new CertificateException();
            }
        } while (response != HttpURLConnection.HTTP_OK);

        try (InputStream download = connection.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certs = (List<X509Certificate>) cf.generateCertificates(download);
        }

        return new ArrayList<>(certs);
    }

    /**
     * Ordena uma lista de certificados para que a ordem reflita a cadeia de certificação
     * @param certs A lista de certificados a ser ordenada
     * @param signerCert O certificado do assinante, isto é, o nível mais baixo na cadeia de certificação
     * @return Uma lista de certificados ordenada de acordo com a cadeia de certificação
     * @throws AIAException exceção caso algum certificado não tenha as informações de seu emissor
     */
    private static List<X509Certificate> orderCertList(List<X509Certificate> certs, X509Certificate signerCert) throws AIAException {

        Map<String, X509Certificate> map = new HashMap<>();
        List<X509Certificate> orderedList = new ArrayList<>();

        for (X509Certificate c : certs) {
            map.put(c.getSubjectX500Principal().toString(), c);
        }

        String name = signerCert.getSubjectX500Principal().toString();
        String issuerName = signerCert.getIssuerX500Principal().toString();
        X509Certificate certificate = map.get(name);

        try {
            do {
                orderedList.add(certificate);
                name = issuerName;
                certificate = map.get(name);
                issuerName = certificate.getIssuerX500Principal().toString();
            } while (!name.equals(issuerName));
        } catch (NullPointerException e) {
            throw new AIAException(NO_ISSUER_MATCH + name);
        }

        orderedList.add(map.get(name));

        return orderedList;

    }

}
