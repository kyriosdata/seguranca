/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertValuesException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertificationPathException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esse atributo é usado para guardar as informações de certificados da
 * assinatura.
 * Ele deve conter no mínimo todos os certificados que o atributo
 * {@link CompleteCertificateRefs} referencia, mais o certificado do assinante.
 * Sendo assim, ele deve conter todos os certificados do caminho de
 * certificação, e o certificado da âncora de confiança. O
 * {@link CompleteCertificateRefs} não guarda o certificado do assinante.
 * 
 * Esquema do atributo CertificateValues retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="CertificateValues" type="CertificateValuesType"/>
 * 
 * <xsd:complexType name="CertificateValuesType">
 * <xsd:choice minOccurs="0" maxOccurs="unbounded">
 * 	<xsd:element name="EncapsulatedX509Certificate" type="EncapsulatedPKIDataType"/>
 * 	<xsd:element name="OtherCertificate" type="AnyType"/>
 * </xsd:choice>
 * <xsd:attribute name="Id" type="xsd:ID" use="optional"/>
 * </xsd:complexType>
 * }
 * 
 */
public class CertificateValues implements SignatureAttribute {

    public static final String IDENTIFIER = "CertificateValues";
    private static final String STANDARD_ENCODING = "http://uri.etsi.org/01903/v1.2.2#DER";
    /**
     * Lista de certificados
     */
    private List<X509Certificate> certificateValues;
    /**
     * Objeto de verificador
     */
    private SignatureVerifier signatureVerifier;
    /**
     * Certificado do assinante
     */
    private X509Certificate signerCertificate;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Este índide deve ser 0 para este atributo
     * @throws EncodingException
     * @throws SignatureAttributeException
     */
    public CertificateValues(AbstractVerifier signatureVerifier, Integer index) throws EncodingException, SignatureAttributeException {
        this.signatureVerifier = (SignatureVerifier) signatureVerifier;
        XadesSignature signature = this.signatureVerifier.getSignature();
        Element encodedAttribute = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(encodedAttribute);
    }

    /**
     * Cria o atributo certificateValues a partir de uma lista de certificados.
     * 
     * @param signerCertificate O certificado do assinante
     * @param certificates Lista de certificados especificados pelo atributo e
     *            que serão armazenados no atributo
     * 
     * @throws CertValuesException
     */
    public CertificateValues(X509Certificate signerCertificate, List<X509Certificate> certificates) throws CertificationPathException,
            CertValuesException {
        List<X509Certificate> completeListCertificates = new ArrayList<X509Certificate>();
        if (signerCertificate == null) {
            throw new CertValuesException(CertValuesException.NULL_SIGNER_CERTIFICATE);
        }
        this.signerCertificate = signerCertificate;
        completeListCertificates.add(this.signerCertificate);
        completeListCertificates.addAll(certificates);
        this.certificateValues = new ArrayList<X509Certificate>();
        this.certificateValues.add(signerCertificate);
        this.certificateValues.addAll(certificates);
    }

    /**
     * Construtor usado quando se quer obter um {@link CertificateValues}
     * @param genericEncoding Codificação do atributo XML obtido da assinatura
     * @throws EncodingException
     */
    public CertificateValues(Element genericEncoding) throws EncodingException {
        this.decode(genericEncoding);
    }

    /**
     * Usado para obter os certificados passados na construção do certificado.
     * Este método só funciona quando o atributo foi construído pelo construtor
     * do {@link SignatureVerifier}.
     * 
     * @return Lista de certificados armazenados pelo atributo
     * 
     * @throws CertValuesException
     */
    public List<X509Certificate> getCertValues() throws CertValuesException {
        List<X509Certificate> x509Certificates = new ArrayList<X509Certificate>(this.certificateValues);
        return x509Certificates;
    }

    /**
     * Retorna o certificado do assinante
     * @return O certificado do assinante
     */
    public X509Certificate getSignerCertificate() {
        return this.signerCertificate;
    }

    /**
     * Decodifica o atributo @ CertificateValues} a partir da sua codificação
     * padrão obtida da assinatura.
     * 
     * @param attributeElement O atributo codificado
     * 
     * @throws EncodingException
     */
    private void decode(Element attributeElement) throws EncodingException {
        NodeList certificateValuesNodeList = attributeElement.getChildNodes();
        this.certificateValues = new ArrayList<X509Certificate>();
        for (int i = 0; i < certificateValuesNodeList.getLength(); i++) {
            Element certificateElement = (Element) certificateValuesNodeList.item(i);
            CertificateFactory certificateFactory = null;
            try {
                certificateFactory = CertificateFactory.getInstance("X.509");
            } catch (CertificateException e) {
                throw new EncodingException("Não foi possível instanciar o certificateFactory.", e);
            }
            ByteArrayInputStream byteInputStream = new ByteArrayInputStream(Base64.decode(certificateElement.getTextContent()));
            Certificate certificate = null;
            try {
                certificate = certificateFactory.generateCertificate(byteInputStream);
            } catch (CertificateException e) {
                throw new EncodingException("Não foi possível gerar certificado.", e);
            }
            this.certificateValues.add((X509Certificate) certificate);
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return CertificateValues.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     */
    @Override
    public void validate() throws SignatureAttributeException, EncodingException {
        int numberOfCertValueAttributes = 0;
        for (String identifier : this.signatureVerifier.getSignature().getAttributeList()) {
            if (identifier.equals(this.getIdentifier())) {
                numberOfCertValueAttributes++;
            }
        }
        if (numberOfCertValueAttributes > 1) {
            SignatureAttributeException signatureAttributeException = new CertValuesException(CertValuesException.DUPLICATED_ATTRIBUTE);
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        List<String> attributeList = this.signatureVerifier.getSignature().getAttributeList();
        if (!attributeList.contains(CompleteCertificateRefs.IDENTIFIER)) {
            SignatureAttributeException signatureAttributeException = new CertValuesException(
                    CertValuesException.CERTIFICATE_REFS_NOT_FOUND);
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        Element completeCertificateRefsEncoding = this.signatureVerifier.getSignature().getEncodedAttribute(
                CompleteCertificateRefs.IDENTIFIER, 0);
        CompleteCertificateRefs completeCertificateRefs = new CompleteCertificateRefs(completeCertificateRefsEncoding);
        List<CertID> certIDListType = completeCertificateRefs.getCertIDs();
        boolean equalBytes = false;
        Iterator<X509Certificate> certificateValuesIterator = this.certificateValues.iterator();
        for (CertID certID : certIDListType) {
            String algorithm = certID.getAlgorithm();
            String digestMethodName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm);
            byte[] certIDTypeDigestValue = certID.getCertificateDigest();
            while ((!equalBytes) && certificateValuesIterator.hasNext()) {
                X509Certificate cert = certificateValuesIterator.next();
                byte[] encapsulatedPKIDataTypeHash = null;
                try {
                    encapsulatedPKIDataTypeHash = this.getHash(cert.getEncoded(), digestMethodName);
                } catch (CertificateEncodingException e) {
                    throw new SignatureAttributeException(SignatureAttributeException.HASH_FAILURE, e.getStackTrace());
                }
                equalBytes = this.compareBytes(certIDTypeDigestValue, encapsulatedPKIDataTypeHash);
            }
            if (!equalBytes) {
                CertValuesException certValuesException = new CertValuesException(CertValuesException.INVALID_CERTIFICATE, certID.getName());
                certValuesException.setCritical(this.isSigned());
                throw certValuesException;
            }
            equalBytes = false;
            certificateValuesIterator = this.certificateValues.iterator();
        }
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
     * Calcula o hash dos bytes
     * @param encoded Os bytes a serem utilizados no cálculo
     * @param algorithm O algoritmo a ser utilizado
     * @return O valor do hash dos bytes dados
     * @throws SignatureAttributeException
     */
    private byte[] getHash(byte[] encoded, String algorithm) throws SignatureAttributeException {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(noSuchAlgorithmException.getMessage(), noSuchAlgorithmException.getStackTrace());
        }
        messageDigest.update(encoded);
        return messageDigest.digest();
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = null;
        try {
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException parserConfigurationException) {
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + CertificateValues.IDENTIFIER,
                    parserConfigurationException.getStackTrace());
        }
        Document document = documentBuilder.newDocument();
        Element certificateValuesElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CertificateValues");

        for (X509Certificate certificate : this.certificateValues) {
            Element certificateElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:EncapsulatedX509Certificate");
            String base64CertificateValue = null;
            try {
                base64CertificateValue = new String(Base64.encode(certificate.getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new SignatureAttributeException("Não foi possível passar os bytes do certificado pra base64.", e.getStackTrace());
            }
            certificateElement.setTextContent(base64CertificateValue);
            Element encodingElement = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "Encoding");
            encodingElement.setTextContent(STANDARD_ENCODING);
            certificateValuesElement.appendChild(certificateElement);
        }
        return certificateValuesElement;
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
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return true;
    }
}
