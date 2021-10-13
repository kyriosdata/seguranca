package br.ufsc.labsec.signature.repository.mac;

import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;

/**
 * Esta classe lida com a seleção de identidades
 */
public class MacIdentitySelector {

    private boolean isIdentitySelected;
    private String selectedIdentity;
    private MacRepository smartCardRepository;

    /**
     * @param windowsRepository Componente {@link MacRepository}
     */
    public MacIdentitySelector(MacRepository windowsRepository) {
        this.smartCardRepository = windowsRepository;
    }

    /**
     * @return Identidades disponíveis para uso
     */
    public List<String> getAvailableIdentities() {
        Enumeration<String> aliases = null;
        try {
            aliases = this.smartCardRepository.getKeyStore().aliases();
        } catch (KeyStoreException e) {
            Application.logger.log(Level.SEVERE, "", e);
        }
        List<String> aliasesList = new ArrayList<String>();
        while (aliases.hasMoreElements()) {
            aliasesList.add(aliases.nextElement());
        }

        return aliasesList;
    }

    /**
     * 
     * @param selectedIdentity Identidade a ser selecionada para o uso
     * @return True se a identidade foi selecionada com sucesso
     * @see MacIdentitySelector#getAvailableIdentities()
     */
    public boolean selectIdentity(String selectedIdentity) {
        this.selectedIdentity = selectedIdentity;
        return this.isIdentitySelected = true;
    }

    /**
     * Reinicia a seleção de identidades
     */
    public void logout() {
        this.selectedIdentity = null;
        this.isIdentitySelected = false;
        this.smartCardRepository.reloadKeyStore();

    }

    /**
     * 
     * @return True se há alguma identidade selecionada
     */
    public boolean isIdentitySelected() {
        return this.isIdentitySelected;
    }

    /**
     * @return O nome da identidade selecionada
     */
    public String getSelectedIdentity() {
        return this.selectedIdentity;
    }
}
