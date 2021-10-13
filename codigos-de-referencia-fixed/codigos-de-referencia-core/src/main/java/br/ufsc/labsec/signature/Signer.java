package br.ufsc.labsec.signature;

import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;

import java.io.InputStream;
import java.util.List;

public interface Signer {
	
	/**
	 * 
	 * @param target O que será assinado
	 * @param policyOid - oid da política usada
	 */
    void selectTarget(InputStream target, String policyOid);
	/**
	 * 
	 * @param target - endereço do arquivo a ser assinado
	 * @param policyOid - oid da política usada
	 */
    void selectTarget(String target, String policyOid);

    boolean sign();
    
    InputStream getSignatureStream();
    
    boolean save();

    void selectAttribute(String attribute);
    
    void unselectAttribute(String attribute);
	
	List<String> getAttributesAvailable();

    /**
     * Retorna os modos possíveis de se assinar no formato deste componente.
     * @return Os modos disponíveis para a assinatura
     */
    List<String> getAvailableModes();

    
    List<String> getMandatedSignedAttributeList();
    

    void setMode(FileFormat mode, String suite);

	List<String> getSignedAttributesAvailable();

	List<String> getUnsignedAttributesAvailable();

	List<String> getPoliciesAvailable();

	List<String> getMandatedUnsignedAttributeList();

	boolean supports(InputStream target, SignerType signerType) throws CertificationPathException, SignerException;
}
