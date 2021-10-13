package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.util.List;

import br.ufsc.labsec.signature.ContentToBeSigned;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesContainerGenerator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;


/**
 * Esta interface é implementada pelas classes e {@link XadesContainerGenerator}.
 * Não deve ser utilizada pelo usuário. 
 */
public interface ContainerGenerator {
	
	/**
	 * Determina o conteúdo que será assinado
	 * @param contentsToBeSigned O conteúdo para assinatura
	 * @throws PbadException
	 * @throws ToBeSignedException
	 */
	public void setContentsToBeSigned(List<ContentToBeSigned> contentsToBeSigned) throws PbadException, ToBeSignedException;
	
	/**
	 * Determina quais atributos serão usados no processo de assinatura
	 * @param attributeList	Lista de atributos a serem inseridos na assinatura
	 * @throws SignatureAttributeException
	 */
	public void setAttributes(List<SignatureAttribute> attributeList) throws SignatureAttributeException;
	
	/**
	 * Gera a assinatura a partir dos atributos e conteúdos informados
	 * @return Um contêiner de assinatura que contém a assinatura gerada
	 * @throws SignatureAttributeException
	 * @throws AlgorithmException
	 * @throws EncodingException
	 * @throws PbadException
	 * @throws ToBeSignedException
	 */
	public SignatureContainer generate() throws SignatureAttributeException, AlgorithmException, EncodingException, PbadException, ToBeSignedException;

	/**
	 * Seleciona o assinante que será usado no processo de assinatura
	 * @param signer os dados do assinante
	 */
	public void setSigner(SignerData signer);

}