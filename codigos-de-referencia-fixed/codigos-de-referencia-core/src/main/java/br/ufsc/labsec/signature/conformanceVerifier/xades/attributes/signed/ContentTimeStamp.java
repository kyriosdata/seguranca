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
 * O atributo ContentTimeStamp representa o carimbo do tempo do conteúdo do dado
 * assinado antes de ele ser assinado.
 * 
 * Oid e esquema do atributo id-countersignature retirado da RFC 3126:
 *
 *  id-aa-ets-contentTimestamp OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) 
 *  pkcs(1) pkcs-9(9) smime(16) id-aa(2) 20}
 * 
 * ContentTimestamp ::= TimeStampToken
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc3126.txt">RFC 3126</a>
 */
public class ContentTimeStamp implements SignatureAttribute {

    public static final String IDENTIFIER = "ContentTimeStamp";
    /**
     * Objeto de verificador
     */
    private AbstractVerifier verifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * 
     * @param verifier Usado para criar e verificar o atributo.
     * @param index Índice usado para selecionar o atributo.
     * @throws SignatureAttributeException
     */
    public ContentTimeStamp(AbstractVerifier verifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = verifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.verifier = verifier;
    }

    /**
     * Constrói um objeto {@link ContentTimeStamp}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public ContentTimeStamp(Element attributeEncoded) throws SignatureAttributeException {
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
        return ContentTimeStamp.IDENTIFIER;
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
        return true;
    }
}
