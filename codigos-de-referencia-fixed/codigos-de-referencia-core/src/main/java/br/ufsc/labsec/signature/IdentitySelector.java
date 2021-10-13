package br.ufsc.labsec.signature;

import java.util.List;

/**
 * Interface para seleção de um identificador
 */
public interface IdentitySelector {
    
    /**
     * Retorna a lista de identificadores
     * @return Lista de identificadores
     */
    List<String> getAvailableIdentities();

    /**
     * Selecionar identificador
     * @param selectedIdentity String
     * @return Indica se foi selecionado com sucesso
     */
    boolean selectIdentity(String selectedIdentity);
    
    /**
     * Logout
     */
    void logout();

	boolean selectProfile(String selectedIdentity);

	List<String> getAvailableProfiles();

	String getSelectedIdentity();

	boolean isIdentitySelected();

}
