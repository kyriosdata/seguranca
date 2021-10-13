/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo CommitmentTypeIndication identifica o tipo de compromisso assumido
 * pelo signatário.
 * 
 * Esquema do atributo CommitmentTypeIndication retirado do ETSI TS 101 903:
 *
 * {@code
 * <xsd:element name="CommitmentTypeIndication" type="CommitmentTypeIndicationType"/>
 * 
 * <xsd:complexType name="CommitmentTypeIndicationType">
 * <xsd:sequence>
 * <xsd:element name="CommitmentTypeId"
 * type="ObjectIdentifierType"/>
 * <xsd:choice>
 * <xsd:element name="ObjectReference" type="xsd:anyURI"
 * maxOccurs="unbounded"/>
 * <xsd:element name="AllSignedDataObjects"/>
 * </xsd:choice>
 * <xsd:element name="CommitmentTypeQualifiers"
 * type="CommitmentTypeQualifiersListType" minOccurs="0"/>
 * </xsd:sequence>
 * </xsd:complexType>
 * }
 */
public class CommitmentTypeIndication implements SignatureAttribute {

    public static final String IDENTIFIER = "CommitmentTypeIndication";
    /**
     * Objeto de verificador
     */
    private AbstractVerifier verifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * 
     * @param verifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public CommitmentTypeIndication(AbstractVerifier verifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = verifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.verifier = verifier;
    }

    /**
     * Constrói um objeto {@link CommitmentTypeIndication}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public CommitmentTypeIndication(Element attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link CommitmentTypeIndication}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Element attributeEncoded) throws SignatureAttributeException {
        // TODO Auto-generated method stub
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return CommitmentTypeIndication.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_IS_NOT_IMPLEMENTED_YET);
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {
        throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_IS_NOT_IMPLEMENTED_YET);
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
        return false;
    }
}
