/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.CommitmentTypeIndication;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertificateRefsException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo CompleteCertificateRefs contém uma lista de referências aos
 * certificados usados na validação da assinatura.
 * Este atributo deve conter apenas todos certificados do caminho de
 * certificação do assinante, incluindo o certificado da Autoridade
 * Certificadora, e excluindo o certificado do signatário.
 * Somente uma instância deste atributo é permitida na assinatura.
 * 
 * Esquema do atributo CompleteCertificateRefs retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="CompleteCertificateRefs" type="CompleteCertificateRefsType"/>
 *  
 * <xsd:complexType name="CompleteCertificateRefsType"> 
 * <xsd:sequence> 
 * 	<xsd:element name="CertRefs" type="CertIDListType" /> 
 * </xsd:sequence> 
 * <xsd:attribute name="Id" type="xsd:ID" use="optional"/> 
 * </xsd:complexType>
 * }
 */
public class CompleteCertificateRefs implements SignatureAttribute, CertSelector {

    public static final String IDENTIFIER = "CompleteCertificateRefs";
    /**
     * Lista de informações dos certificados
     */
    private List<CertID> certs;
    /**
     * Algoritmo utilizado
     */
    private String algorithm;
    /**
     * Um conjunto de hashs de certificados presentes no atributo para agilizar
     * a busca dentro de um certStore
     */
    private Set<String> certificateIdentifierSet;
    /**
     * Objeto de verificador
     */
    private SignatureVerifier signatureVerifier;

    /**
     * Construtor utilizado para verificação. É passado o verificador donde
     * pode-se obter a assinatura e o indice desse atributo para decodifica-lo
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public CompleteCertificateRefs(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = (SignatureVerifier) signatureVerifier;
        XadesSignature signature = this.signatureVerifier.getSignature();
        Element attributeEncoded = signature.getEncodedAttribute(CompleteCertificateRefs.IDENTIFIER, index);
        this.decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link CompleteCertificateRefs}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public CompleteCertificateRefs(Element genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

    /**
     * Contrutor utilizado para a criação do atributo. É passada a lista dos
     * certificados utilizados nessa assinatura e o algoritmo que será utilizado
     * para tirar os hashs dos certificados
     * 
     * @param certificates A lista de certificados
     * @param digestAlgorithm Algoritmo de hash
     * @throws SignatureAttributeException
     */
    public CompleteCertificateRefs(List<X509Certificate> certificates, String digestAlgorithm) throws SignatureAttributeException {
        if (certificates == null) {
            throw new SignatureAttributeException("Os parâmetros não podem ser nulos ao instanciar um CompleteCertificateRefs");
        }
        if (certificates.size() == 0) {
            throw new SignatureAttributeException("A lista deve conter pelo menos um certificado CompleteCertificateRefs");
        }
        this.certs = new ArrayList<CertID>();
        this.algorithm = digestAlgorithm;
        for (X509Certificate cert : certificates) {
            CertID certId = new CertID();
            certId.setSerialNumber(cert.getSerialNumber());
            certId.setAlgorithm(digestAlgorithm);
            certId.setName(cert.getIssuerDN().getName());
            try {
                certId.setCertificateDigest(this.getCertificateHash(cert));
            } catch (SignatureAttributeException e) {
                throw new SignatureAttributeException("Problema em setar CertificateDigest.", e.getStackTrace());
            }
            this.certs.add(certId);
        }
        this.makeCertificateSet();
    }

    /**
     * Constrói um objeto {@link CommitmentTypeIndication}
     * @param attributeElement O atributo codificado
     */
    private void decode(Element attributeElement) throws SignatureAttributeException {
        Element certRefsElement = (Element) attributeElement.getChildNodes().item(0);
        NodeList certs = certRefsElement.getChildNodes();
        this.certs = new ArrayList<CertID>();
        for (int i = 0; i < certs.getLength(); i++) {
            Element certElement = (Element) certs.item(i);
            byte[] digest = makeDigest(certElement);
            BigInteger serialNumber = makeIssuerSerial(certElement);
            CertID certId = makeCertId(digest, serialNumber);
            this.certs.add(certId);
        }
        this.makeCertificateSet();
    }

    /**
     * Cria um objeto CertID
     * @param digest O hash do certificado
     * @param serialNumber O número de série do certificado
     * @return O objeto criado
     */
    private CertID makeCertId(byte[] digest, BigInteger serialNumber) {
        CertID certId = new CertID();
        certId.setCertificateDigest(digest);
        certId.setSerialNumber(serialNumber);
        certId.setAlgorithm(this.algorithm);
        return certId;
    }

    /**
     * Busca o número de série no nodo do certificado
     * @param certElement O nodo XML do certificado
     * @return O número de série do certificado
     */
    private BigInteger makeIssuerSerial(Element certElement) {
        Element issuerSerialElement = (Element) certElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "IssuerSerial").item(
                0);
        Element issuerNameElement = (Element) issuerSerialElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                "X509IssuerName").item(0);
        Element serialNumberElement = (Element) issuerSerialElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                "X509SerialNumber").item(0);
        CertID certId = new CertID();
        certId.setName(issuerNameElement.getTextContent());
        certId.setSerialNumber(new BigInteger(serialNumberElement.getTextContent()));
        certId.setAlgorithm(this.algorithm);
        return certId.getSerialNumber();
    }

    /**
     * Busca o valor de hash no nodo do certificado
     * @param certElement O nodo XML do certificado
     * @return O valor de hash do certificado
     */
    private byte[] makeDigest(Element certElement) {
        Element certDigestElement = (Element) certElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "CertDigest").item(0);
        Element digestMethodElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,"DigestMethod").item(0);
        this.algorithm = digestMethodElement.getAttribute("Algorithm");
        Element digestValueElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS, "DigestValue")
                .item(0);
        byte[] digestValue = digestValueElement.getTextContent().getBytes();
        CertID certId = new CertID();
        certId.setCertificateDigest((Base64.decode(digestValue)));
        return certId.getCertificateDigest();
    }

    /**
     * Instância um {@link HashSet} para verificar se o certificado é
     * refêrenciado pelo atributo. A utilização do HashSet torna mais veloz a
     * comparação
     */
    private void makeCertificateSet() {
        this.certificateIdentifierSet = new HashSet<String>();
        for (CertID certId : this.certs) {
            String hashBase64 = new String(Base64.encode(certId.getCertificateDigest()));
            this.certificateIdentifierSet.add(hashBase64);
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return CompleteCertificateRefs.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @SuppressWarnings("unchecked")
    @Override
    public void validate() throws SignatureAttributeException {
        // FIXME: Arrumar relação entre os componentes
        int numberOfCertRefsAttributes = 0;
        for (String identifier : this.signatureVerifier.getSignature().getAttributeList()) {
            if (identifier.equals(this.getIdentifier())) {
                numberOfCertRefsAttributes++;
            }
        }
        if (numberOfCertRefsAttributes > 1) {
            SignatureAttributeException signatureAttributeException = new CertificateRefsException(
                    CertificateRefsException.DUPLICATED_ATTRIBUTE);
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        CertPath certPath = this.signatureVerifier.getSignerCertPath();
        List<X509Certificate> certPathCertificates = (List<X509Certificate>) certPath.getCertificates();
        Set<X509Certificate> certPathSet = new HashSet<X509Certificate>(certPathCertificates);
        Set<CertID> certIdSet = new HashSet<CertID>(this.certs);
        
        if (certPathSet.size() != certIdSet.size()) {
            SignatureAttributeException signatureAttributeException = new CertificateRefsException(
                    CertificateRefsException.WRONG_SIZE_OF_CERTIFICATES);
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        X509Certificate lastCertificate = certPathCertificates.get(certPathCertificates.size() - 1);
        CertificateTrustPoint certificateTrustPoint = this.signatureVerifier.getSignaturePolicy().getTrustPoint(
                lastCertificate.getIssuerX500Principal());
        X509Certificate trustPoint = (X509Certificate) certificateTrustPoint.getTrustPoint();
        List<X509Certificate> certPathToCompare = new ArrayList<X509Certificate>(certPathCertificates.subList(1, certPathCertificates.size()));
        certPathToCompare.add(trustPoint);
        Iterator<X509Certificate> certificateIterator = certPathToCompare.iterator();
        boolean equalBytes = false;
        String actualCertificate = "";
        List<CertID> certIDList = this.certs;
        for (CertID certID : certIDList) {
            String algorithmID = certID.getAlgorithm();
            String algorithmName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmID);

            while ((!equalBytes) && certificateIterator.hasNext()) {
                X509Certificate x509Certificate = certificateIterator.next();
                byte[] x509CertificateHash = this.getCertificateHash(x509Certificate, algorithmName);
                equalBytes = this.compareBytes(certID.getCertificateDigest(), x509CertificateHash);
                actualCertificate = x509Certificate.getSubjectX500Principal().getName();
            }
            if (!equalBytes) {
                CertificateRefsException certificateRefsException = new CertificateRefsException(
                        CertificateRefsException.MISSING_CERTIFICATE, actualCertificate);
                certificateRefsException.setCritical(this.isSigned());
                throw certificateRefsException;
            }
            equalBytes = false;
            certificateIterator = certPathToCompare.iterator();
        }
    }

    /**
     * Calcula o hash do certificado dado
     * @param certificate O certificado
     * @param algorithm O algoritmo a ser utilizado no cálculo
     * @return O hash do certificado
     * @throws SignatureAttributeException
     */
    private byte[] getCertificateHash(X509Certificate certificate, String algorithm) throws SignatureAttributeException {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new CertificateRefsException(noSuchAlgorithmException.getMessage(), noSuchAlgorithmException.getStackTrace());
        }
        try {
            messageDigest.update(certificate.getEncoded());
        } catch (CertificateEncodingException certificateEncodingException) {
            throw new CertificateRefsException(certificateEncodingException.getMessage(), certificateEncodingException.getStackTrace());
        }
        return messageDigest.digest();
    }

    /**
     * Verifica se os bytes são iguais
     * @param expected O byte experado
     * @param actual O byte atual
     * @return Indica se são iguais
     */
    private boolean compareBytes(byte[] expected, byte[] actual) {
        boolean result = expected.length == actual.length;
        int i = 0;
        while (result && i < expected.length) {
            result &= expected[i] == actual[i++];
        }
        return result;
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    public Element getEncoded() throws SignatureAttributeException {
        Document document = null;
        try {
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new SignatureAttributeException("Problema na construção do documento", e.getStackTrace());
        }
        Element completeCertificatesRef = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CompleteCertificateRefs");

        Element certRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CertRefs");
        completeCertificatesRef.appendChild(certRefs);

        for (CertID certId : this.certs) {
            Element cert = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Cert");
            certRefs.appendChild(cert);

            Element certDigest = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CertDigest");
            cert.appendChild(certDigest);

            Element digestMethod = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestMethod");
            digestMethod.setAttribute("Algorithm", certId.getAlgorithm());
            certDigest.appendChild(digestMethod);

            Element digestValue = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestValue");
            digestValue.setTextContent(new String(Base64.encode(certId.getCertificateDigest())));
            certDigest.appendChild(digestValue);

            Element issuerSerial = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:IssuerSerial");
            cert.appendChild(issuerSerial);

            Element x509IssuerName = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:X509IssuerName");
            x509IssuerName.setTextContent(certId.getName());
            issuerSerial.appendChild(x509IssuerName);

            Element x509SerialNumber = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:X509SerialNumber");
            x509SerialNumber.setTextContent(certId.getSerialNumber().toString());
            issuerSerial.appendChild(x509SerialNumber);

        }
        return completeCertificatesRef;
    }

    /**
     * Informa se o atributo é assinado.
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return false;
    }

    /**
     * Calcula o hash do certificado
     * @param certificate O certificado
     * @return O valor do hash do certificado
     * @throws SignatureAttributeException
     */
    private byte[] getCertificateHash(X509Certificate certificate) throws SignatureAttributeException {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(this.algorithm));
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureAttributeException("Problema no messageDigest do CertificateHash", e.getStackTrace());
        }
        try {
            messageDigest.update(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new SignatureAttributeException("Problema no update do messageDigest", e.getStackTrace());
        }
        return messageDigest.digest();
    }

    /**
     * Seleciona os certificados que tem sua identificação gravada no atributo
     * em questão
     * @param certificate O certificado a ser comparado
     */
    @Override
    public boolean match(Certificate certificate) {
        boolean result = certificate instanceof X509Certificate;
        if (result) {
            MessageDigest digester = null;
            try {
                digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(this.algorithm));
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {

                /* Não é possível afirmar que os certificados são iguais */
                noSuchAlgorithmException.printStackTrace();
                result = false;
            }
            byte[] hash = null;
            try {
                hash = digester.digest(certificate.getEncoded());
            } catch (CertificateEncodingException certificateEncodingException) {
                /* Não é possível afirmar que os certificados são iguais */
                certificateEncodingException.printStackTrace();
                result = false;
            }
            String hashBase64 = new String(Base64.encode(hash));
            result = this.certificateIdentifierSet.contains(hashBase64);
        }
        return result;
    }

    /**
     * Construtor usado para clonar o objeto
     */
    private CompleteCertificateRefs() {
    }

    /**
     * Retorna um objeto identico à instância para qual a mensagem foi enviada.
     * As alterações feitas no objeto retornado não afetam a instância antes
     * mencionada.
     */
    @Override
    public CompleteCertificateRefs clone() {
        CompleteCertificateRefs clone = new CompleteCertificateRefs();
        clone.algorithm = this.algorithm;
        clone.certificateIdentifierSet = new HashSet<String>(this.certificateIdentifierSet);
        clone.certs = new ArrayList<CertID>(this.certs);
        return clone;
    }

    /**
     * Retorna a lista de CertIDs
     * @return A lista de CertIDs
     */
    public List<CertID> getCertIDs() {
        return new ArrayList<CertID>(this.certs);
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return true;
    }
}
