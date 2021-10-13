/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo AllDataObjectTimeStamp contém um carimbo do tempo computado antes
 * da produção da assinatura, sobre uma sequência formada por TODOS os elementos
 * ds:Reference dentro do elemento ds:SignedInfo referenciando o que o assinante
 * quiser assinar, exceto o elemento SignedProperties.
 *
 * Esquema do atributo AllDataObjectTimeStamp retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="AllDataObjectsTimeStamp" type="XAdESTimeStampType"/>
 * }
 */
public class AllDataObjectTimeStamp implements SignatureAttribute {

    public static final String IDENTIFIER = "AllDataObjectTimeStamp";

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * 
     * @param verifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * 
     * @throws SignatureAttributeException
     * @throws SignatureAttributeNotFoundException
     */
    public AllDataObjectTimeStamp(AbstractVerifier verifier, Integer index) throws SignatureAttributeException,
            SignatureAttributeNotFoundException {
        Element attributeEncoded = verifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link AllDataObjectTimeStamp}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public AllDataObjectTimeStamp(Element attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

	/**
	 * Constrói um objeto {@link AllDataObjectTimeStamp}
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
        return AllDataObjectTimeStamp.IDENTIFIER;
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
	 * Informa se o atributo é assinado
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
