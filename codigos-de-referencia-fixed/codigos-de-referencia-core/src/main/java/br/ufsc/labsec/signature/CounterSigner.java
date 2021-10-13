package br.ufsc.labsec.signature;

import java.util.List;

import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

public interface CounterSigner {

	void selectTarget(String target, String signedContent, String signaturePolicy);

	/**
     * Define qual a assinatura dentro do arquivo que será verificada
     */
	void selectSignature(String signatureName);

	void selectAttribute(String attribute);

	void unselectAttribute(String attribute);
	
	/**
     * Informa quais as assinaturas presentes no arquivo indicado
     * 
     * @throws SignatureAttributeException
     * @throws EncodingException
     */
    List<String> getAvailableSignatures();

	List<String> getMandatedSignedAttributeList();

	List<String> getSignedAttributesAvailable();

	List<String> getUnsignedAttributesAvailable();

	List<String> getPoliciesAvailable();

	List<String> getMandatedUnsignedAttributeList();

	public boolean counterSign();
	
	boolean isSignature(String filePath);

	boolean needSignedContent();

}
