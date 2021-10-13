/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.CommitmentTypeIndication;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa o atributo RefsOnlyTimeStamp.
 * 
 * Esquema do atributo RefsOnlyTimeStamp retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="RefsOnlyTimeStamp" type="XAdESTimeStampType"/>
 * }
 */
public class RefsOnlyTimeStamp implements SignatureAttribute {

    public static final String IDENTIFIER = "RefsOnlyTimeStamp";
    /**
     * Objeto de verificador
     */
    private SignatureVerifier verifier;

    /**
     * Construtor usado apenas na verificação.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public RefsOnlyTimeStamp(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = verifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.verifier = (SignatureVerifier) verifier;
    }

    /**
     * Constrói um objeto {@link RefsOnlyTimeStamp}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public RefsOnlyTimeStamp(Element attributeEncoded) throws SignatureAttributeException {
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
        return RefsOnlyTimeStamp.IDENTIFIER;
    }

    /**
     * Retorna a tag XML do atributo
     * @return Retorna "XAdES:RefsOnlyTimeStamp"
     */
    protected String getElementName() {
        return "XAdES:RefsOnlyTimeStamp";
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
        return false;
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
