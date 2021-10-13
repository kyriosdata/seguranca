package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.util.List;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;

/**
 * Esta interface engloba métodos comuns entre assinaturas.
 */
public interface AbstractSignature
{
	/**
	 * Adiciona um atributo não-assinado
	 * @param attribute atributo a ser adicionado na assintura
	 * @throws PbadException
	 * @throws SignatureAttributeException
	 */
	void addUnsignedAttribute(SignatureAttribute attribute) throws PbadException, SignatureAttributeException;

	/**
	 * Remove um atributo não-assinado
	 * @param attributeId Identificador do atributo a ser removido
	 * @param index O índice do atributo que será removido
	 * @throws EncodingException 
	 */
	void removeUnsignedAttribute(String attributeId, int index) throws SignatureAttributeException, EncodingException;
	
	/**
	 * Substitui um atributo não assinado qualquer. Útil quando é necessário adicionar mais
	 * atributos em um carimbo de tempo, por exemplo
	 * 
	 * @param attribute O atributo que foi atualizado
	 * @param index O índice do atributo em relação aos seus similares, ou seja,
	 *              se há três carimbos do tempo da assinatura e o segundo vai ser
	 *              atualizado o indice é 1
	 * @throws PbadException
	 * @throws SignatureAttributeException
	 */
	void replaceUnsignedAttribute(SignatureAttribute attribute, Integer index) throws PbadException,
		SignatureAttributeException;
	
	/**
	 * Retorna a lista de identificadores dos atributos utilizados
	 * no processo de assinatura. Se o atributo for do tipo CAdES, o identificador
	 * será um OID e se for do tipo XAdES, será o nome de uma tag
	 * 
	 * @return lista de identificadores de cada atributo utilizado na assinatura
	 */
	List<String> getAttributeList();

	/**
	 * Retorna o atributo correspondente ao identificador ou índice dado
	 * @param identifier o identificador do atributo
	 * @param index o índice do atributo
	 * @return o elemento XML do atributo na assinatura
	 * @throws SignatureAttributeNotFoundException
	 */
	Element getEncodedAttribute(String identifier, Integer index) throws SignatureAttributeNotFoundException;
}
