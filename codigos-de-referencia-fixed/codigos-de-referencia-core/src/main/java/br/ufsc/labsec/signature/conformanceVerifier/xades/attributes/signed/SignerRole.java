/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo SignerRole representa o papel do assinante com a compania ou a
 * organização. Este atributo contém uma sequência de papéis que o assinante
 * pode adotar.
 *
 * Esquema do atributo SignerRole retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="SignerRole" type="SignerRoleType"/>
 * 
 * <xsd:complexType name="SignerRoleType">
 * <xsd:sequence>
 * <xsd:element name="ClaimedRoles" type="ClaimedRolesListType" minOccurs="0"/>
 * <xsd:element name="CertifiedRoles" type="CertifiedRolesListType" minOccurs="0"/>
 * </xsd:sequence>
 * </xsd:complexType>
 * 
 * <xsd:complexType name="ClaimedRolesListType">
 * <xsd:sequence>
 * <xsd:element name="ClaimedRole" type="AnyType" maxOccurs="unbounded"/>
 * </xsd:sequence>
 * </xsd:complexType>
 * 
 * <xsd:complexType name="CertifiedRolesListType">
 * <xsd:sequence>
 * <xsd:element name="CertifiedRole" type="EncapsulatedPKIDataType" maxOccurs="unbounded"/>
 * </xsd:sequence>
 * </xsd:complexType>
 * }
 */
public class SignerRole implements SignatureAttribute {

    public static final String IDENTIFIER = "SignerRole";/**
     * Objeto de verificador
     */
    private AbstractVerifier signatureVerifier;
    /**
     * Lista de papéis do atributo de certificado
     */
    protected List<String> claimedRoles;
    /**
     * Lista de atributos de certificado
     */
    protected List<AttributeCertificate> certifiedRoles;

    /**
     * <p>
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usaddo no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * </p>
     * 
     * @param verifier Usado para criar e verificar o atributo.
     * @param index Índice usado para selecionar o atributo.
     * @throws SignatureAttributeException exceção na criação do elemento
     */
    public SignerRole(AbstractVerifier verifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = verifier.getSignature().getEncodedAttribute(this.getIdentifier());
        decode(attributeEncoded);
        this.signatureVerifier = verifier;
    }

    /**
     * Construtor usado na criação do atributo.
     * 
     * @param claimedRoles Papéis do atributo de certificado
     * @param attributeCertificates Atributos de certificado
     * 
     * @throws SignatureAttributeException
     */
    public SignerRole(List<String> claimedRoles, List<AttributeCertificate> attributeCertificates) {
        this.claimedRoles = claimedRoles;
        certifiedRoles = attributeCertificates;
    }

    /**
     * Constrói um objeto {@link SignerRole}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException Exceção em caso de erro no documento
     */
    public SignerRole(Element attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Cria as listas da classe com base no elemento passado
     * @param attribute O elemento XML
     * @throws SignatureAttributeException Exceções no documento
     */
    private void decode(Element attribute) throws SignatureAttributeException {

        NodeList nodeList = attribute.getChildNodes();
        Node claimedRoles = nodeList.item(0);
        NodeList claimedRolesList = claimedRoles.getChildNodes();

        Node certifiedRoles = nodeList.item(1);
        NodeList certifiedRolesList = certifiedRoles.getChildNodes();

        for (int i = 0 ; i < claimedRolesList.getLength(); i++){
            this.claimedRoles.add(claimedRolesList.item(i).getTextContent());
        }

        
        for (int i = 0 ; i < certifiedRolesList.getLength(); i++){
            ASN1Object attrib = null;
            try {
                attrib = ASN1Sequence.fromByteArray(Base64.decode(certifiedRolesList.item(i).getTextContent().getBytes()));
            } catch (Exception e1) {
                throw new SignatureAttributeException("Problema em acessar os certificados no documento");
            }
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return SignerRole.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {

        List<String> attributeList = this.signatureVerifier.getSignature().getAttributeList();
        int cont = 0;
        for (String attribute : attributeList) {
            if (attribute.equals(this.getIdentifier()))
                cont++;
        }
        if (cont > 1)
            throw new SignatureAttributeException("A assinatura contém mais do que um attributo " + this.getIdentifier());
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

        Element signerRole = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SignerRole");

        Element claimedRoles = document.createElement("claimedRoles");
        Element certifiedRoles = document.createElement("certifiedRoles");

        signerRole.appendChild(claimedRoles);
        signerRole.appendChild(certifiedRoles);

        for (String s : this.claimedRoles) {
            Element claimedRole = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ClaimedRole");
            claimedRole.setTextContent(s);
            claimedRoles.appendChild(claimedRole);
        }

        for (AttributeCertificate role : this.certifiedRoles) {
            Element certifiedRole = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CertifiedRole");
            try {
                certifiedRole.setTextContent(new String(Base64.encode(role.getEncoded())));
            } catch (Exception e) {
                throw new SignatureAttributeException("Problema em codificar os certificados no documento");
            }
            certifiedRoles.appendChild(certifiedRole);
        }

        return signerRole;
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
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return true;
    }
}
