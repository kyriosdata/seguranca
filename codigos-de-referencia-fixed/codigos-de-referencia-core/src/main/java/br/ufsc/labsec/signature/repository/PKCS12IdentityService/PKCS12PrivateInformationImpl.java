package br.ufsc.labsec.signature.repository.PKCS12IdentityService;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.PrivateInformation;


public class PKCS12PrivateInformationImpl implements PrivateInformation {

	private PKCS12Repository pkcs12Repository;
	private PKCS12 pkcs12;

	public PKCS12PrivateInformationImpl(PKCS12Repository pkcs12Repository) {
		this.pkcs12Repository = pkcs12Repository;
	}
	
    public PKCS12PrivateInformationImpl(PKCS12 pkcs12) {
        this.pkcs12 = pkcs12;
    }

	@Override
	public PrivateKey getPrivateKey() {
		if (!this.pkcs12Repository.isIdentitySelected()) {
			this.pkcs12Repository.showIdentitySelection();
		}

		PrivateKey privateKey = null;
		int count = 0;
		String message = "Digite sua senha";
		do {
			char[] password = this.pkcs12Repository.identityConfirmer.confirm(message);
			try {
				this.pkcs12Repository.reloadPkcs12(password);
				privateKey = (PrivateKey) this.pkcs12Repository.getPkcs12().getKey(this.pkcs12Repository.getAlias(),
						password);
			} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
				message = "Senha incorreta, digite novamente";
				Application.logger.log(Level.FINEST, "", e);
			}
			count++;
			
		} while (privateKey == null && count < 3);
		return privateKey;
	}
	

	@Override
	public X509Certificate getCertificate() {
		if (!this.pkcs12Repository.isIdentitySelected()) {
			this.pkcs12Repository.showIdentitySelection();
		}

		X509Certificate signerCertificate = null;
			try {
				signerCertificate = (X509Certificate) this.pkcs12Repository
						.getPkcs12().getCertificate(
								this.pkcs12Repository.getAlias());
				
			} catch (KeyStoreException e) {
				Application.logger.log(Level.SEVERE, "", e);
			}
		return signerCertificate;
	}


}
