/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.CommitmentTypeIndication;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.RevocationValuesException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esse atributo é usado para guardar as informações de revogação da assinatura.
 * Ele deve conter no mínimo todos as CRLs e respostas OCSPs que o atributo
 * {@link CompleteRevocationRefs} referencia.
 * Esquema do atributo RevocationValues retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="RevocationValues" type="RevocationValuesType"/>
 * <xsd:complexType name="RevocationValuesType">
 * <xsd:sequence>
 * 	<xsd:element name="CRLValues" type="CRLValuesType" minOccurs="0"/>
 * 	<xsd:element name="OCSPValues" type="OCSPValuesType" minOccurs="0"/>
 * 	<xsd:element name="OtherValues" type="OtherCertStatusValuesType" minOccurs="0"/>
 * </xsd:sequence>
 * <xsd:attribute name="Id" type="xsd:ID" use="optional"/>
 * </xsd:complexType>
 * }
 */
public class RevocationValues implements SignatureAttribute {

    public static final String IDENTIFIER = "RevocationValues";
    private static final String STANDARD_ENCODING = "http://uri.etsi.org/01903/v1.2.2#DER";
    /**
     * Objeto de verificador
     */
    private SignatureVerifier signatureVerifier;
    /**
     * Lista de CRLs
     */
    private List<X509CRL> crlValues;
    /**
     * Lista de respostas OCSP
     */
    private List<BasicOCSPResponse> ocspValues;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Este índide deve ser 0 para este atributo
     * @throws SignatureAttributeException
     */
    public RevocationValues(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = (SignatureVerifier) signatureVerifier;
        XadesSignature signature = this.signatureVerifier.getSignature();
        Element genericEncoding = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(genericEncoding);

    }

    /**
     * Construtor usado quando se quer obter um {@link RevocationValues}
     * @param genericEncoding Codificação do atributo XML obtido da assinatura
     * @throws SignatureAttributeException
     */
    public RevocationValues(Element genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

    /**
     * Cria o atributo a partir de uma lista de CRLs e de respostas OCSPs. Pelo
     * menos um desses parâmetros deve existir e não ser vazio. Os atributos
     * referenciados aqui devem ter no mínimo os mesmos certificados e/ou
     * respostas referenciadas no atributo {@link CompleteRevocationRefs}.
     * 
     * @param crlValues Lista com as LCRs utilizadas para validar o caminho
     * @param ocspValues Lista com respostas OCSP utilizadas para validar o
     *            caminho
     * 
     * @throws SignatureAttributeException
     */
    public RevocationValues(List<X509CRL> crlValues, List<BasicOCSPResponse> ocspValues) throws SignatureAttributeException {
        if (crlValues == null && ocspValues == null) {
            throw new RevocationValuesException(RevocationValuesException.MISSING_ATTRIBUTES);
        }
        if (crlValues != null && ocspValues == null) {
            if (crlValues.size() == 0) {
                throw new RevocationValuesException(RevocationValuesException.MISSING_ATTRIBUTES);
            }
        }
        if (ocspValues != null && crlValues == null) {
            if (ocspValues.size() == 0) {
                throw new RevocationValuesException(RevocationValuesException.MISSING_ATTRIBUTES);
            }
        }
        if (crlValues != null && ocspValues != null) {
            if (crlValues.size() == 0 && ocspValues.size() == 0) {
                throw new RevocationValuesException(RevocationValuesException.MISSING_ATTRIBUTES);
            }
        }
        if (crlValues != null) {
            this.crlValues = new ArrayList<X509CRL>();
            X509CRL crlValue = null;
            for (X509CRL value : crlValues) {
                crlValue = value;
                this.crlValues.add(crlValue);
            }
        }
        if (ocspValues != null) {
            this.ocspValues = new ArrayList<BasicOCSPResponse>();
            BasicOCSPResponse basicOcspResponse = null;
            for (BasicOCSPResponse ocspValue : ocspValues) {
                basicOcspResponse = ocspValue;
                this.ocspValues.add(basicOcspResponse);
            }
        }
    }

    /**
     * Constrói um objeto {@link RevocationValues}
     * @param attributeElement O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Element attributeElement) throws SignatureAttributeException {
        NodeList crlValuesNodeList = attributeElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "CRLValues");
        NodeList crlElementList;
        if (crlValuesNodeList.getLength() > 0) {
//            crlElement = (Element) crlValuesNodeList.item(0);
            this.crlValues = new ArrayList<X509CRL>();

            for (int i = 0; i < crlValuesNodeList.getLength(); i++) {
                crlElementList = (NodeList) crlValuesNodeList.item(i);
                
                for (int j = 0; j < crlElementList.getLength(); j++) {
                	
                	Element crlElement = (Element) crlElementList.item(j);
                	
	                CertificateFactory certificateFactory = null;
	                try {
	                    certificateFactory = CertificateFactory.getInstance("X.509");
	                } catch (CertificateException e) {
	                    e.printStackTrace(); // TODO
	                }
	                
	                ByteArrayInputStream byteInputStream = new ByteArrayInputStream(Base64.decode(crlElement.getTextContent()));
	                CRL crl = null;
	                try {
	                    crl = certificateFactory.generateCRL(byteInputStream);
	                } catch (CRLException e) {
	                    e.printStackTrace();
	                }
	
	                this.crlValues.add((X509CRL) crl);
                }
            }
        }
        NodeList ocspValuesNodeList = attributeElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "OCSPValues");
        if (ocspValuesNodeList.getLength() > 0) {
            Element ocspElement = (Element) ocspValuesNodeList.item(0);
            this.ocspValues = new ArrayList<BasicOCSPResponse>();
            for (int i = 0; i < ocspElement.getChildNodes().getLength(); i++) {
                NodeList encapsulatedPKIDataElementList = (NodeList) ocspElement.getChildNodes().item(i);
                
                for(int j = 0; j < encapsulatedPKIDataElementList.getLength(); j++) {

                    // Possibilita a extração do conteúdo de texto mesmo se
                    // for um Element Node ou um simples Text Node.
                    String textContent;
                    Node item = encapsulatedPKIDataElementList.item(j);
                    if (item.getNodeType() == Node.ELEMENT_NODE) {
                        Element encapsulatedPKIDataElement = (Element) item;
                        textContent = encapsulatedPKIDataElement.getTextContent();
                    } else {
                        textContent = item.getTextContent();
                    }
                	
	                ASN1Sequence sequence = null;
	                try {
	                    sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(Base64.decode(textContent));
	                } catch (DOMException e) {
	                    e.printStackTrace();
	                } catch (IOException e) {
	                    e.printStackTrace(); // TODO
	                }
	                this.ocspValues.add(BasicOCSPResponse.getInstance(sequence));
                }
            }
        }
    }

    /**
     * Retorna a lista de CRLs usada para construir o atributo. Se a lista não
     * foi passada na construção do atributo, retorna nulo
     * @return A lista de CRLs
     * @throws RevocationValuesException
     */
    public List<X509CRL> getCrlValues() throws RevocationValuesException {
        // List<X509CRL> crlValues = null;
        // if (this.crlValues != null) {
        // crlValues = new ArrayList<X509CRL>();
        // CertificateFactory certificateFactory;
        // try {
        // certificateFactory = CertificateFactory.getInstance("X.509");
        // } catch (CertificateException certificateException) {
        // throw new
        // RevocationValuesException(certificateException.getMessage(),
        // certificateException.getStackTrace());
        // }
        // for (X509CRL encapsulatedCRLValue : this.crlValues) {
        // ByteArrayInputStream crlBytes = new
        // ByteArrayInputStream(encapsulatedCRLValue.getValue());
        // X509CRL x509Crl;
        // try {
        // x509Crl = (X509CRL) certificateFactory.generateCRL(crlBytes);
        // } catch (CRLException crlException) {
        // throw new RevocationValuesException(crlException.getMessage(),
        // crlException.getStackTrace());
        // }
        // crlValues.add(x509Crl);
        // }
        // }
        return new ArrayList<X509CRL>(this.crlValues);
    }

    /**
     * Retorna a lista de respostas OCSP usada para construir o atributo. Se a
     * lista não foi passada na construção do atributo retorna nulo
     * @return A lista de respostas OCSP
     * @throws RevocationValuesException
     */
    public List<BasicOCSPResponse> getOcspValues() throws RevocationValuesException {
        // List<BasicOCSPResponse> ocspValues = null;
        // if (this.ocspValues != null) {
        // ocspValues = new ArrayList<BasicOCSPResponse>();
        // for (EncapsulatedPKIDataType encapsulatedOCSPValue : this.ocspValues)
        // {
        // ASN1Sequence ocspValueSequence;
        // try {
        // ocspValueSequence = (ASN1Sequence)
        // ASN1Sequence.fromByteArray(encapsulatedOCSPValue.getValue());
        // } catch (IOException ioException) {
        // throw new RevocationValuesException(ioException.getMessage(),
        // ioException.getStackTrace());
        // }
        // BasicOCSPResponse basicOcspResponse;
        // basicOcspResponse = new BasicOCSPResponse(ocspValueSequence);
        // ocspValues.add(basicOcspResponse);
        // }
        // }
        return new ArrayList<BasicOCSPResponse>(this.ocspValues);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return RevocationValues.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        int numberOfCertValueAttributes = 0;
        for (String identifier : this.signatureVerifier.getSignature().getAttributeList()) {
            if (identifier.equals(this.getIdentifier())) {
                numberOfCertValueAttributes++;
            }
        }
        if (numberOfCertValueAttributes > 1) {
            RevocationValuesException revocationValuesException = new RevocationValuesException(
                    RevocationValuesException.DUPLICATED_ATTRIBUTE);
            revocationValuesException.setCritical(this.isSigned());
            throw revocationValuesException;
        }
        List<String> attributeList = this.signatureVerifier.getSignature().getAttributeList();
        if (!attributeList.contains(CompleteRevocationRefs.IDENTIFIER)) {
            RevocationValuesException revocationValuesException = new RevocationValuesException(
                    RevocationValuesException.COMPLETE_REVOCATION_REFS_NOT_FOUND);
            revocationValuesException.setCritical(this.isSigned());
            throw revocationValuesException;
        }
        Element completeRevocationRefsEncoding = this.signatureVerifier.getSignature().getEncodedAttribute(
                CompleteRevocationRefs.IDENTIFIER, 0);
        CompleteRevocationRefs completeRevocationRefs = new CompleteRevocationRefs(completeRevocationRefsEncoding);
        List<CRLRefs> crlRefs = completeRevocationRefs.getCrlRefs();
        boolean equalBytes = false;
        if (crlRefs != null) {
            if (crlRefs.size() > 0) {
                if (this.crlValues == null) {
                    RevocationValuesException revocationValuesException = new RevocationValuesException(
                            RevocationValuesException.INVALID_NUMBER_OF_CRLS);
                    revocationValuesException.setCritical(this.isSigned());
                    throw revocationValuesException;
                }
                if (this.crlValues.size() == 0) {
                    RevocationValuesException revocationValuesException = new RevocationValuesException(
                            RevocationValuesException.INVALID_NUMBER_OF_CRLS);
                    revocationValuesException.setCritical(this.isSigned());
                    throw revocationValuesException;
                }
                if (this.crlValues.size() < crlRefs.size()) {
                    RevocationValuesException revocationValuesException = new RevocationValuesException(
                            RevocationValuesException.INVALID_NUMBER_OF_CRLS);
                    revocationValuesException.setCritical(this.isSigned());
                    throw revocationValuesException;
                }
                Iterator<X509CRL> crlValuesIterator = this.crlValues.iterator();
                for (CRLRefs crlRef : crlRefs) {
                    String algorithm = crlRef.getAlgorithm();
                    String digestMethodName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm);
                    String crlRefTypeDigestValue = crlRef.getDigestValue();
                    String encapsulatedHexString = "";
                    while ((!equalBytes) && crlValuesIterator.hasNext()) {
                        X509CRL crl = crlValuesIterator.next();
                        byte[] encapsulatedPKIDataTypeHash = null;
                        try {
                            encapsulatedPKIDataTypeHash = this.getHash(crl.getEncoded(), digestMethodName);
                            encapsulatedHexString =
                                    java.util.Base64.getEncoder().encodeToString(encapsulatedPKIDataTypeHash);
                        } catch (CRLException e) {
                            e.printStackTrace(); // TODO
                        }
                        equalBytes =
                                crlRefTypeDigestValue.equals(encapsulatedHexString);
                    }
                    if (!equalBytes) {
                        RevocationValuesException revocationValuesException = new RevocationValuesException(
                                RevocationValuesException.MISSING_CRL_CERTIFICATE);
                        revocationValuesException.setCritical(this.isSigned());
                        throw revocationValuesException;
                    }
                    equalBytes = false;
                    crlValuesIterator = this.crlValues.iterator();
                }
            }
        }
        List<OCSPRefs> ocspRefsList = completeRevocationRefs.getOcspRefs();
        if (ocspRefsList != null) {
            if (ocspRefsList.size() > 0) {
                if (this.ocspValues == null) {
                    RevocationValuesException revocationValuesException = new RevocationValuesException(
                            RevocationValuesException.INVALID_NUMBER_OF_OCSPS);
                    revocationValuesException.setCritical(this.isSigned());
                    throw revocationValuesException;
                }
                if (this.ocspValues.size() == 0) {
                    RevocationValuesException revocationValuesException = new RevocationValuesException(
                            RevocationValuesException.INVALID_NUMBER_OF_OCSPS);
                    revocationValuesException.setCritical(this.isSigned());
                    throw revocationValuesException;
                }
                if (this.ocspValues.size() < ocspRefsList.size()) {
                    RevocationValuesException revocationValuesException = new RevocationValuesException(
                            RevocationValuesException.INVALID_NUMBER_OF_OCSPS);
                    revocationValuesException.setCritical(this.isSigned());
                    throw revocationValuesException;
                }
                Iterator<BasicOCSPResponse> ocspValuesIterator = this.ocspValues.iterator();
                for (OCSPRefs ocspRef : ocspRefsList) {
                    String algorithm = ocspRef.getAlgorithm();
                    String digestMethodName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm);
                    byte[] ocspRefTypeDigestValue = ocspRef.getDigestValue().getBytes();
                    while ((!equalBytes) && ocspValuesIterator.hasNext()) {
                        BasicOCSPResponse basicOcspResponse = ocspValuesIterator.next();
                        byte[] encapsulatedPKIDataTypeHash = null;
                        try {
                            encapsulatedPKIDataTypeHash = this.getHash(basicOcspResponse.getEncoded(), digestMethodName);
                        } catch (IOException e) {
                            e.printStackTrace(); // TODO
                        }
                        equalBytes = this.compareBytes(ocspRefTypeDigestValue, encapsulatedPKIDataTypeHash);
                    }
                    if (!equalBytes) {
                        RevocationValuesException revocationValuesException = new RevocationValuesException(
                                RevocationValuesException.MISSING_OCSP_RESPONSE);
                        revocationValuesException.setCritical(this.isSigned());
                        throw revocationValuesException;
                    }
                    equalBytes = false;
                    ocspValuesIterator = this.ocspValues.iterator();
                }
            }
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
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    noSuchAlgorithmException.getMessage(), noSuchAlgorithmException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
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
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + RevocationValues.IDENTIFIER,
                    parserConfigurationException.getStackTrace());
        }
        Document document = documentBuilder.newDocument();
        Element revocationValuesElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:RevocationValues");
        if (this.crlValues != null) {
            Element crlValuesElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CRLValues");
            for (X509CRL encapsulatedCRLValue : this.crlValues) {
                Element encapsulatedCrlValueElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS,
                        "XAdES:EncapsulatedCRLValue");
                String base64CertificateValue = null;
                try {
                    base64CertificateValue = new String(Base64.encode(encapsulatedCRLValue.getEncoded()));
                } catch (CRLException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                encapsulatedCrlValueElement.setTextContent(base64CertificateValue);
                encapsulatedCrlValueElement.setAttribute("Encoding", STANDARD_ENCODING);
                crlValuesElement.appendChild(encapsulatedCrlValueElement);
            }
            revocationValuesElement.appendChild(crlValuesElement);
        }
        if (this.ocspValues != null) {
            Element ocspValuesElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:OCSPValues");
            for (BasicOCSPResponse encapsulatedOCSPValue : this.ocspValues) {
                Element encapsulatedOcspValueElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS,
                        "XAdES:EncapsulatedOCSPValue");
                String base64OcspValue = null;
                try {
                    base64OcspValue = new String(Base64.encode(encapsulatedOCSPValue.getEncoded()));
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                encapsulatedOcspValueElement.setTextContent(base64OcspValue);
                encapsulatedOcspValueElement.setAttribute("Encoding", STANDARD_ENCODING);
                ocspValuesElement.appendChild(encapsulatedOcspValueElement);
            }
            revocationValuesElement.appendChild(ocspValuesElement);
        }
        return revocationValuesElement;
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
