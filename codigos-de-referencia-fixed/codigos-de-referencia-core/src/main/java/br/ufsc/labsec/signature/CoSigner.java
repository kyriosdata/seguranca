package br.ufsc.labsec.signature;

import java.util.List;


public interface CoSigner {
	
	
	boolean canCoSign(String signatureAdress);
	
	/**
	 * @param signatureAdress Endereço do arquivo a ser assinado
	 * @param contentPath Endereço do conteúdo assinado
	 * @param policyOid Identificador da política usada
	 */
    void selectTarget(String signatureAdress, String contentPath, String policyOid);

    boolean coSign();

    void selectAttribute(String attribute);
    
    void unselectAttribute(String attribute);

    
    List<String> getMandatedSignedAttributeList();
   

	List<String> getSignedAttributesAvailable();

	List<String> getUnsignedAttributesAvailable();

	List<String> getPoliciesAvailable();

	List<String> getMandatedUnsignedAttributeList();

	
}
