/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertRefReq;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.MandatedCertRefException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SigningCertificateException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo SigningCertificate é designado para previnir o ataque de
 * substituição, e para permitir um conjunto restrito de certificados de
 * autorização a serem usados na verificação da assinatura. Esta versão
 * representa uma referência do certificado do signatário utilizando o algoritmo
 * de hash SHA1.
 *
 * SigningCertificate implementa SigningCertificateInterface, que por sua vez
 * extende as interfaces SignatureAttribute, que representa um atributo da
 * assinatura, e CertSelector, que é utilizado para selecionar certificados de
 * um CertStore utilizando critérios.
 *
 * O SigningCertificate pode ser composto por um identificador e
 * obrigatoriamente pelo hash do certificado dos signatário, sendo que o hash é
 * utilizado como critério no CertSelector para encontrar o certificado no
 * CertStore.
 *
 * Esquema do atributo SigningCertificate retirado do ETSI TS 101 903:
 *
 * {@code
 * <xsd:element name="SigningCertificate" type="CertIDListType"/><br>
 * 
 * <xsd:complexType name="CertIDListType"><br>
 * <xsd:sequence><br>
 * <xsd:element name="Cert" type="CertIDType"<br>
 * maxOccurs="unbounded"/><br>
 * </xsd:sequence><br>
 * </xsd:complexType><br>
 * <xsd:complexType name="CertIDType"><br>
 * 
 * <xsd:complexType name="CertIDType"><br>
 * <xsd:sequence><br>
 * <xsd:element name="CertDigest" type="DigestAlgAndValueType"/><br>
 * <xsd:element name="IssuerSerial" type="ds:X509IssuerSerialType"/><br>
 * </xsd:sequence><br>
 * <xsd:attribute name="URI" type="xsd:anyURI" use="optional"/><br>
 * </xsd:complexType><br>
 * 
 * <xsd:complexType name="DigestAlgAndValueType"><br>
 * <xsd:sequence><br>
 * <xsd:element ref="ds:DigestMethod"/><br>
 * <xsd:element ref="ds:DigestValue"/><br>
 * </xsd:sequence><br>
 * </xsd:complexType><br>
 * }
 */
public class SigningCertificate implements SigningCertificateInterface {

    public static final String IDENTIFIER = "SigningCertificate";
    
    private static final String ALGORITHM = "Algorithm";

    /**
     * Elemento XML do atributo
     */
    protected Element signingCertificateElement;
    /**
     * Objeto de verificador
     */
    protected SignatureVerifier signatureVerifier;
    /**
     * O algoritmo utilizado para cálculo de hash
     */
    private String algorithm;
    /**
     * O nome do emissor
     */
    private String issuerName;
    /**
     * O número de série do emissor
     */
    private BigInteger issuerSerial;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo.
     * Este método decodifica todos os certificados que foram adicionados no
     * atributo SigningCertificate. Ou seja, ele funciona para os casos
     * SignerOnly e FullPath.
     * 
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Este valor deve ser 0
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    public SigningCertificate(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = (SignatureVerifier) signatureVerifier;
        XadesSignature xmlSignature = (XadesSignature) this.signatureVerifier.getSignature();
        Element signatureElement = xmlSignature.getSignatureElement();
        Element signingCertificate = (Element) signatureElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                IDENTIFIER).item(0);
        this.decode(signingCertificate);
    }

    /**
     * Constrói um objeto {@link SigningCertificate}
     * @param genericEncoding O atributo codificado
     * @throws EncodingException Caso ocorra algum erro relativo ao certificado.
     */
    public SigningCertificate(Element genericEncoding) throws EncodingException {
        this.decode(genericEncoding);
    }

    /**
     * Inibe o uso do construtor vazio default.
     */
    private SigningCertificate() {
    }

    /**
     * Cria o atributo id-aa-signingCertificate a partir de uma lista de
     * certificados. Este método decodifica todos os certificados que foram
     * adicionados no {@link SigningCertificate}. Ou seja, ele funciona para
     * os casos SignerOnly e FullPath.
     * @param certs Lista de certificados que serão guardados no atributo
     *            signing certificate da assinatura
     * @param digestAlgorithm O algoritmo de cálculo de hash
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    public SigningCertificate(List<X509Certificate> certs, String digestAlgorithm) throws SignatureAttributeException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = null;
        try {
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException parserConfigurationException) {
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + SigningCertificate.IDENTIFIER,
                    parserConfigurationException.getStackTrace());
        }
        Document document = documentBuilder.newDocument();
        this.algorithm = digestAlgorithm;
        this.signingCertificateElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SigningCertificate");
        for (X509Certificate certificate : certs) {
            Element certDigest = this.getCertDigest(certificate, digestAlgorithm, document);
            Element issuerSerial = this.getIssuerSerial(certificate, document);
            Element cert = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Cert");
            cert.appendChild(certDigest);
            cert.appendChild(issuerSerial);
            this.signingCertificateElement.appendChild(cert);
        }
    }

    /**
     * Constrói um objeto {@link SigningCertificate}
     * @param signingCertificate O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Element signingCertificate) {
        this.signingCertificateElement = signingCertificate;
        Element certId = (Element) this.signingCertificateElement.getFirstChild();
        Element certDigest = (Element) certId.getFirstChild();
        Element digestMethod = (Element) certDigest.getFirstChild();
        
        this.algorithm = digestMethod.getAttribute(ALGORITHM);
        
        Element issuer = (Element) certId.getLastChild();
        Element issuerNameElement = (Element) issuer.getFirstChild();
        Element issuerSerialElement = (Element) issuer.getLastChild();
        
        this.issuerName = issuerNameElement.getFirstChild().getNodeValue();
        this.issuerSerial = new BigInteger(issuerSerialElement.getFirstChild().getNodeValue());
    }

    /**
     * Cria um nodo com o valor do IssuerSerial
     * @param certificate Certificado do qual será retirado o IssuerSerial
     * @param document O documento XML
     * @return O elemento XML contendo o IssuerSerial.
     */
    private Element getIssuerSerial(X509Certificate certificate, Document document) {
        Element issuerName = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:X509IssuerName");
        issuerName.setTextContent(certificate.getIssuerX500Principal().toString());
        Element issuerSerialNumber = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:X509SerialNumber");
        issuerSerialNumber.setTextContent(certificate.getSerialNumber().toString());
        Element issuerSerial = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:IssuerSerial");
        issuerSerial.appendChild(issuerName);
        issuerSerial.appendChild(issuerSerialNumber);
        return issuerSerial;
    }

    /**
     * Cria um nodo com o valor de hash do certificado
     * @param certificate O certificado que sera retirado o CertDigest
     * @param algorithm O algoritmo utilizado para o cálculo do hash
     * @param document O documento XML
     * @return Um elemento XML contendo o CertDigest
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    private Element getCertDigest(X509Certificate certificate, String algorithm, Document document) throws SignatureAttributeException {
        Element digestMethod = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestMethod");
        digestMethod.setAttribute(ALGORITHM, algorithm);
        Element digestValue = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestValue");
        try {
            digestValue.setTextContent(new String(Base64.encode(this.getCertificateHash(certificate))));
        } catch (DOMException domException) {
            throw new SignatureAttributeException("Não foi possível criar um nodo para o hash do certificado");
        }
        Element certDigest = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CertDigest");
        certDigest.appendChild(digestMethod);
        certDigest.appendChild(digestValue);
        return certDigest;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return SigningCertificate.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        NodeList certs = this.signingCertificateElement.getChildNodes();
        int certsLength = certs.getLength();
        SignaturePolicyInterface signaturePolicy = this.signatureVerifier.getSignaturePolicy();
        CertRefReq certRefReq = signaturePolicy.getSigningCertRefReq();
        CertPath certPath = this.signatureVerifier.getSignerCertPath();
        if (certRefReq != null && certRefReq.equals(CertRefReq.SIGNER_ONLY)) {
            if (certsLength != 1) {
                // é signerOnly mas tem mais de um certificado
                throw new SignatureAttributeException(MandatedCertRefException.ISNT_SIGNER_ONLY);
            }
        } else {
            validadeFullPath(certs, certsLength, certPath);
        }
    }

    /**
     * Verifica o hash dos certificados no caminho de certificação
     * @param certs Os certificados
     * @param certsLength Quantidade de certificados.
     * @param certPath O caminho de certificação
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    private void validadeFullPath(NodeList certs, int certsLength, CertPath certPath) throws SignatureAttributeException {
        if (certsLength > 1) {
            for (int i = 0; i < certsLength; i++) {
                Element cert = (Element) certs.item(i);
                X509Certificate certificate = (X509Certificate) certPath.getCertificates().get(i);
                if (!this.compareIssuerSerial((Element) cert.getLastChild(), certificate)
                        || !this.compareCertificateHash(cert, certificate)) {
                    // nova exceção: os hashs dos certificados não batem
                    throw new SignatureAttributeException(SigningCertificateException.INVALID_CERTIFICATE_HASH);
                }
            }
        } else {
            // É fullPath mas só tem um certificado, ou nenhum
            throw new SignatureAttributeException(MandatedCertRefException.ISNT_FULL_PATH);
        }
    }

    /**
     * Confere o hash de um elemento com o certificado
     * @param cert Elemento referente ao certificado
     * @param certificate O certificado
     * @return Indica se o hash está correto
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    private boolean compareCertificateHash(Element cert, X509Certificate certificate) throws SignatureAttributeException {
        Node certDigest = cert.getFirstChild();
        Node digestValueElement = certDigest.getLastChild();
        String digestValue = digestValueElement.getTextContent();
        byte[] expected = Base64.decode(digestValue);
        byte[] obtained = this.getCertificateHash(certificate);
        return this.compareBytes(expected, obtained);
    }

    /**
     * Confere o IssuerSerial de um elemento com o certificado.
     * @param issuerSerial O elemento referente ao IssuerSerial.
     * @param certificate O certificado
     * @return Indica se o IssuerSerial do certificado é o mesmo que o número dado
     */
    private boolean compareIssuerSerial(Element issuerSerial, X509Certificate certificate) {
        Element issuerNameElement = (Element) issuerSerial.getFirstChild();
        String issuerName = issuerNameElement.getTextContent();
        Element serialElement = (Element) issuerSerial.getLastChild();
        BigInteger serial = new BigInteger(serialElement.getTextContent().trim());
        String nameFromCertificate = certificate.getIssuerX500Principal().toString();
        BigInteger serialFromCertificate = certificate.getSerialNumber();
        boolean equals = serial.equals(serialFromCertificate);
        equals &= issuerName.equals(nameFromCertificate);
        return equals;
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {
        return this.signingCertificateElement;
    }

    /**
     * Informa se o atributo é assinado.
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return true;
    }

    /**
     * Verifica se o certificado dado é o mesmo que está no atributo
     * @param certificate O certificado a ser comparado
     * @return Indica se o certificado dado é o mesmo que está no atributo
     */
    @Override
    public boolean match(Certificate certificate) {
        boolean match = true;
        X509Certificate x509Certificate = (X509Certificate) certificate;
        Element cert = (Element) this.signingCertificateElement.getFirstChild();
        Element issuerSerial = (Element) cert.getLastChild();
        Element issuerNameElement = (Element) issuerSerial.getFirstChild();
        Element serialElement = (Element) issuerSerial.getLastChild();
        String issuerName = issuerNameElement.getTextContent();
        BigInteger serial = new BigInteger(serialElement.getTextContent());

		String issuerPrincipalName = x509Certificate.getIssuerX500Principal().toString().replace(", ", ",");
        issuerName = issuerName.replace(", ", ",");
        
        match = issuerPrincipalName.equals(issuerName);

        match &= serial.equals(x509Certificate.getSerialNumber());
        byte[] incommingCertificate = null;
        if (match) {
            try {
                incommingCertificate = this.getCertificateHash(x509Certificate);
            } catch (SignatureAttributeException e) {
                match = false;
            }
        }
        if (match) {
            Node certId = this.signingCertificateElement.getFirstChild();
            Node certDigest = certId.getFirstChild();
            Node digestValueElement = certDigest.getLastChild();
            String digestValue = digestValueElement.getTextContent();
            byte[] expected = Base64.decode(digestValue);
            match = this.compareBytes(expected, incommingCertificate);
        }
        return match;
    }

    /**
     * Faz uma cópia deste objeto
     * @return Uma cópia do objeto
     */
    @Override
    public CertSelector clone() {
        SigningCertificate clone = new SigningCertificate();
        clone.signingCertificateElement = this.signingCertificateElement;
        clone.signatureVerifier = this.signatureVerifier;
        return clone;
    }

    /**
     * Obtém todos os certificados que foram guardados no atributo
     * SigningCertificate da assinatura.
     * 
     * @return Certificados que foram guardados no atributo signing certificate
     *         da assinatura.
     */
    public Element getSigningCertificateElement() {
        return this.signingCertificateElement;
    }

    /**
     * Calcula o hash do certificado
     * @param certificate O certificado
     * @return O Hash do certificado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    private byte[] getCertificateHash(X509Certificate certificate) throws SignatureAttributeException {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(this.algorithm));
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureAttributeException(SigningCertificateException.NO_SUCH_ALGORITHM_EXCEPTION);
        }
        try {
            messageDigest.update(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new SignatureAttributeException(SigningCertificateException.CERTIFICATE_ENCODING_EXCEPTION);
        }
        return messageDigest.digest();
    }

    /**
     * Verifica se os bytes são iguais
     * @param expected O byte experado.
     * @param actual O byte atual.
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
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return true;
    }

    /**
     * Retorna o nome do emissor
     * @return O nome do emissor
     */
    public String getIssuerName() {
        return this.issuerName;
    }

    /**
     * Retorna o SerialNumber
     * @return O SerialNumber
     */
    public BigInteger getSerialNumber() {
        return this.issuerSerial;
    }
}
