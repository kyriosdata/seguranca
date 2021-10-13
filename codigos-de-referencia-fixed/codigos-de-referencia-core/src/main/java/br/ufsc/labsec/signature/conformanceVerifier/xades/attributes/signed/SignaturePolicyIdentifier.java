/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

//import br.ufsc.labsec.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo SignaturePolicyIdentifier define um conjunto de regras para a
 * criação e validação de uma assinatura.
 * 
 * Esquema do atributo SignaturePolicyIdentifier retirado do ETSI TS 101 903:
 *
 * {@code
 * <xsd:element name="SignaturePolicyIdentifier" type="SignaturePolicyIdentifierType"/>
 * 
 * <xsd:complexType name="SignaturePolicyIdentifierType">
 * <xsd:choice>
 * <xsd:element name="SignaturePolicyId" type="SignaturePolicyIdType"/>
 * <xsd:element name="SignaturePolicyImplied"/>
 * </xsd:choice>
 * </xsd:complexType>
 * 
 * <xsd:complexType name="SignaturePolicyIdType">
 * <xsd:sequence>
 * <xsd:element name="SigPolicyId" type="ObjectIdentifierType"/>
 * <xsd:element ref="ds:Transforms" minOccurs="0"/>
 * <xsd:element name="SigPolicyHash" type="DigestAlgAndValueType"/>
 * <xsd:element name="SigPolicyQualifiers"
 * type="SigPolicyQualifiersListType" minOccurs="0"/>
 * </xsd:sequence>
 * </xsd:complexType>
 * 
 * <xsd:complexType name="SigPolicyQualifiersListType">
 * <xsd:sequence>
 * <xsd:element name="SigPolicyQualifier" type="AnyType"
 * maxOccurs="unbounded"/>
 * </xsd:sequence>
 * </xsd:complexType>
 * }
 */
public class SignaturePolicyIdentifier implements SignatureAttribute {

    public static final String IDENTIFIER = "SignaturePolicyIdentifier";
    // protected static final String JAXB_CLASSES = "br.ufsc.labsec.xml";
    /**
     * O valor de hash da PA
     */
    protected byte[] sigPolicyHash;
    /**
     * O identificador da política
     */
    protected String sigPolicyId;
    /**
     * A URL da política
     */
    protected String sigPolicyUrl;
    /**
     * O método de cálculo de hash da política
     */
    protected String digestMethodId;
    /**
     * Objeto de verificador
     */
    protected SignatureVerifier verifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usaddo no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * 
     * @param verifier Usado para criar e verificar o atributo.
     * @param index Índice Usado para selecionar o atributo.
     * @throws SignatureAttributeException Exceção no documento
     */
    public SignaturePolicyIdentifier(AbstractVerifier verifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = verifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.verifier = (SignatureVerifier) verifier;
    }

    /**
     * Cria o atributo SignaturePolicyIdentifier a partir dos parâmetros
     * necessários para a criação do atributo.
     * 
     * @param sigPolicyId Identificador da política de assinatura
     * @param digestMethodId Identificador do algoritmo de resumo
     *            criptográfico usado para gerar o resumo criptográfico da
     *            assinatura
     * @param policyHash Valor do resumo criptográfico obtido da política
     *            assinatura
     * @param policyUrl URL que indica onde a política de assinatura pode ser
     *            encontrada
     */
    public SignaturePolicyIdentifier(String sigPolicyId, String digestMethodId, byte[] policyHash, String policyUrl) {
        this.setSigPolicyId(sigPolicyId);
        this.setDigestMethodId(digestMethodId);
        this.setSigPolicyHash(policyHash);
        this.setSigPolicyUrl(policyUrl);
    }

    /**
     * Constrói um objeto {@link SignaturePolicyIdentifier}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException Exceção no documento
     */
    public SignaturePolicyIdentifier(Element attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Decodificar o elemento
     * @param signaturePolicyIdentifierElement O nodo da PA
     * @throws SignatureAttributeException Exceção no documento
     */
    private void decode(Element signaturePolicyIdentifierElement) throws SignatureAttributeException {
        Element signaturePolicyId = (Element) signaturePolicyIdentifierElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                "SignaturePolicyId").item(0);
        Element sigPolicyId = (Element) signaturePolicyId.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "SigPolicyId").item(0);
        Element identifier = (Element) sigPolicyId.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "Identifier").item(0);
        this.sigPolicyId = identifier.getTextContent();
        Element sigPolicyHash = (Element) signaturePolicyId.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "SigPolicyHash")
                .item(0);
        Element digestMethod = (Element) sigPolicyHash.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS, "DigestMethod").item(0);
        this.digestMethodId = digestMethod.getAttribute("Algorithm");
        Element digestValue = (Element) sigPolicyHash.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS, "DigestValue").item(0);
        this.sigPolicyHash = digestValue.getTextContent().getBytes();
        Element sigPolicyQualifiers = (Element) signaturePolicyId.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                "SigPolicyQualifiers").item(0);
        Element sigPolicyQualifier = (Element) sigPolicyQualifiers.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                "SigPolicyQualifier").item(0);
        Element spuri = (Element) sigPolicyQualifier.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "SPURI").item(0);
        this.sigPolicyUrl = spuri.getTextContent();
    }

    /**
     * Atribuir a URL da política
     * @param policyUrl A URL da política
     */
    private void setSigPolicyUrl(String policyUrl) {
        this.sigPolicyUrl = policyUrl;
    }

    /**
     * Atribuir o valor de hash da política
     * @param policyHash O valor de hash da política
     */
    private void setSigPolicyHash(byte[] policyHash) {
        this.sigPolicyHash = policyHash;
    }

    /**
     * Atribuir o algoritmo de cálculo de hash
     * @param digestMethodId O algoritmo de cálculo de hash
     */
    private void setDigestMethodId(String digestMethodId) {
        this.digestMethodId = digestMethodId;
    }

    /**
     * Atribuir o identificador da política
     * @param sigPolicyId O identificador da política
     */
    private void setSigPolicyId(String sigPolicyId) {
        this.sigPolicyId = sigPolicyId;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    public String getIdentifier() {
        return SignaturePolicyIdentifier.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        SignaturePolicyInterface expectedSignaturePolicy = this.verifier.getSignaturePolicy();
        String expectedSignaturePolicyHash = new String(Base64.encode(expectedSignaturePolicy.getSignPolicyHash()));
        if (!expectedSignaturePolicyHash.isEmpty()) {
            if (new String(this.sigPolicyHash).compareTo(expectedSignaturePolicyHash) != 0) {
                throw new SignatureAttributeException("O valor do resumo criptográfico não é equivalente ao esperado.");
            }
        } else {
            throw new SignatureAttributeException(SignatureAttributeException.INVALID_PA_OID);
        }
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {

        Document document = null;
        try {
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new SignatureAttributeException("Problema em gerar o documento");
        }

        Element signaturePolicyIdentifier = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SignaturePolicyIdentifier");

        Element signaturePolicyId = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SignaturePolicyId");

        Element sigPolicyId = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SigPolicyId");
        Element identifier = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Identifier");
        identifier.setTextContent(this.sigPolicyId);
        sigPolicyId.appendChild(identifier);
        signaturePolicyId.appendChild(sigPolicyId);

        Element sigPolicyHash = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SigPolicyHash");
//        sigPolicyHash.setTextContent(new String(this.sigPolicyHash));
        Element digestMethod = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestMethod");
        Element digestValue = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestValue");
        digestValue.setTextContent(new String(this.sigPolicyHash));
        digestMethod.setAttribute("Algorithm", this.digestMethodId);
        sigPolicyHash.appendChild(digestMethod);
        sigPolicyHash.appendChild(digestValue);
        signaturePolicyId.appendChild(sigPolicyHash);

        Element sigPolicyQualifiers = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SigPolicyQualifiers");
        Element sigPolicyQualifier = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SigPolicyQualifier");

        Element spuri = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SPURI");
        spuri.setTextContent(this.sigPolicyUrl);
        sigPolicyQualifier.appendChild(spuri);

        sigPolicyQualifiers.appendChild(sigPolicyQualifier);
        signaturePolicyId.appendChild(sigPolicyQualifiers);


        signaturePolicyIdentifier.appendChild(signaturePolicyId);



        return signaturePolicyIdentifier;
    }

    /**
     * Retorna o identificador da política
     * @return O identificador da política
     */
    public String getSignaturePolicyId() {
        return this.sigPolicyId;
    }

    /**
     * Obtém o valor do resumo criptográfico obtido da política assinatura.
     * @return O valor de hash da política
     */
    public byte[] getSigPolicyHash() {
        return Base64.encode(this.sigPolicyHash);
    }

    /**
     * Obtém o OID da política de assinatura.
     * @return O identificador da política
     */
    public String getSigPolicyId() {
        return this.sigPolicyId;
    }

    /**
     * Obtém a URL que indica onde a politica de assinatura pode ser encontrada.
     * @return A URL da política
     */
    public String getSigPolicyUrl() {
        return this.sigPolicyUrl;
    }

    /**
     * Obtém o OID do algoritmo de resumo criptográfico usado para gerar o
     * resumo criptográfico da assinatura.
     * @return O algoritmo de cálculo de hash
     */
    public String getDigestMethodId() {
        return this.digestMethodId;
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
     * Retorna a URL da LPA
     * @return {@link String}
     */
    public String getLpaUrl() {
        return getSigPolicyUrl();
    }

    /**
     * Retorna o valor de hash da política
     * @return O valor de hash da política
     */
    public String getSignaturePolicyHashValue() {
        return new String(Base64.encode(this.sigPolicyHash));
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
