package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.util.List;

import org.bouncycastle.asn1.cms.Attribute;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;


/**
 * Esta interface engloba métodos comuns entre assinaturas.
 */
public interface AbstractSignature
{
	/**
	 * Adiciona um atributo não-assinado
	 * @param attribute O atributo a ser adicionado na assinatura
	 * @throws PbadException
	 * @throws SignatureAttributeException
	 */
	void addUnsignedAttribute(SignatureAttribute attribute) throws PbadException, SignatureAttributeException;

	/**
	 * Remove um atributo não-assinado
	 * @param attributeId O identificador do atributo a ser removido
	 * @param index O índice do atributo que será removido
	 * @throws SignatureAttributeNotFoundException
	 */
	void removeUnsignedAttribute(String attributeId, int index) throws SignatureAttributeNotFoundException;
	
	/**
	 * Substitui um atributo não assinado qualquer, útil quando é necessário adicionar mais
	 * atributos em um carimbo de tempo por exemplo
	 * @param attribute O atributo que foi atualizado
	 * @param index O indice do atributo em relação aos seus similares, ou seja, se há três carimbos do tempo da
	 *            assinatura e o segundo vai ser atualizado o indice é 1
	 * @throws PbadException
	 * @throws SignatureAttributeException
	 */
	void replaceUnsignedAttribute(SignatureAttribute attribute, Integer index) throws PbadException,
		SignatureAttributeException;
	
	/**
	 * Retorna a lista de identificadores dos atributos utilizados
	 * no processo de assinatura. Se o atributo for do tipo CAdES, o identificador
	 * será um OID e se for do tipo XAdES, será o nome de uma tag.
	 * @return Lista de identificadores de cada atributo utilizado na assinatura.
	 */
	List<String> getAttributeList();

	/**
	 * Retorna um objeto do atributo desejado
	 * @param identifier O identificador do atributo
	 * @param index Índice do atributo
	 * @return Um objeto do atributo desejado
	 */
	Attribute getEncodedAttribute(String identifier, Integer index) throws SignatureAttributeNotFoundException;
}
