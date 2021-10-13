package br.ufsc.labsec.signature.repository.windows;

import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.IdentitySelector;

/**
 * Esta classe lida com a seleção de identidades
 */
public class WindowsIdentitySelector implements IdentitySelector {

    private boolean isIdentitySelected;
    private String selectedIdentity;
    private WindowsRepository smartCardRepository;

    /**
     * @param windowsRepository Componente {@link WindowsRepository}
     */
    public WindowsIdentitySelector(WindowsRepository windowsRepository) {
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
     * @see WindowsIdentitySelector#getAvailableIdentities()
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

	@Override
	public List<String> getAvailableProfiles() {
		String[] profiles = { "Default" };
		return Arrays.asList(profiles);
	}

	@Override
	public boolean selectProfile(String selectedProfile) {
		return true;
	}
}
