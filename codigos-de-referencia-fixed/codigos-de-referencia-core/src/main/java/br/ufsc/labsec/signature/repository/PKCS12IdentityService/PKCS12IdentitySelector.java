package br.ufsc.labsec.signature.repository.PKCS12IdentityService;

import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.IdentitySelector;

public class PKCS12IdentitySelector implements IdentitySelector {

	private boolean isIdentitySelected;
	private PKCS12Repository pkcs12Repository;
	private String selectedIdentity;

	public PKCS12IdentitySelector(PKCS12Repository pkcs12Repository) {
		this.pkcs12Repository = pkcs12Repository;
	}

	@Override
	public List<String> getAvailableIdentities() {
		Enumeration<String> aliases = null;
		try {
			aliases = this.pkcs12Repository.getPkcs12().aliases();
		} catch (KeyStoreException e) {
			Application.logger.log(Level.SEVERE, "", e);
		}
		List<String> aliasesList = new ArrayList<String>();
		while (aliases.hasMoreElements()) {
			aliasesList.add(aliases.nextElement());
		}
		return aliasesList;
	}

	@Override
	public boolean selectIdentity(String selectedIdentity) {
		this.selectedIdentity = selectedIdentity;
		return this.isIdentitySelected = true;
	}

	@Override
	public void logout() {
		this.selectedIdentity = null;
		this.pkcs12Repository.clear();
		this.isIdentitySelected = false;
	}

	/**
	 * Verifica se é o identificador selecionado
	 * 
	 * @return Indica se é o identificador selecionado
	 */
	public boolean isIdentitySelected() {
		return this.isIdentitySelected;
	}

	/**
	 * Retorna a instância do identificador
	 * 
	 * @return A instância
	 */
	public String getSelectedIdentity() {
		return this.selectedIdentity;
	}

	@Override
	public List<String> getAvailableProfiles() {
		List<String> profiles = new ArrayList<>();
		if (this.pkcs12Repository.getPkcs12() != null) { // Just for a good
															// behavior on the
															// interface
			profiles.add("Default");
		}
		return profiles;
	}

	@Override
	public boolean selectProfile(String selectedProfile) {
		return true;
	}

}
