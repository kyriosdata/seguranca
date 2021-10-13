package br.ufsc.labsec.signature.repository.mac;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;

import javax.swing.JOptionPane;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.PrivateInformation;

/**
 * Serviço para o acesso a informação privada da identidade selecionada
 */
public class MacPrivateInformation implements PrivateInformation {

    private static final String SIGNER_CERTIFICATE_ACCESS_PROBLEM = "Não foi possível obter o certificado do signatário.";
    private static final String PROBLEM = "Problema";
    private static final String PRIVATE_KEY_ACCESS_FAILURE = "Não foi possível obter a referência para a chave privada.";
    private MacRepository smartCardRepository;

    /**
     * 
     * @param windowsRepository Componente de acesso ao repositório do windows
     */
    public MacPrivateInformation(MacRepository windowsRepository) {
        this.smartCardRepository = windowsRepository;
    }

    /**
     * @return Obtém a {@link PrivateKey} da identidade selecionada
     */
    public PrivateKey getPrivateKey() {
        if (!this.smartCardRepository.isIdentitySelected()) {
            this.smartCardRepository.showIdentitySelection();
        }

        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) this.smartCardRepository.getKeyStore().getKey(this.smartCardRepository.getAlias(), null);
        } catch (UnrecoverableKeyException e) {
            Application.logger.log(Level.SEVERE, PRIVATE_KEY_ACCESS_FAILURE, e);
            JOptionPane.showMessageDialog(null, PRIVATE_KEY_ACCESS_FAILURE, PROBLEM, JOptionPane.WARNING_MESSAGE);
        } catch (KeyStoreException e) {
            Application.logger.log(Level.SEVERE, PRIVATE_KEY_ACCESS_FAILURE, e);
            JOptionPane.showMessageDialog(null, PRIVATE_KEY_ACCESS_FAILURE, PROBLEM, JOptionPane.WARNING_MESSAGE);
        } catch (NoSuchAlgorithmException e) {
            Application.logger.log(Level.SEVERE, PRIVATE_KEY_ACCESS_FAILURE, e);
            JOptionPane.showMessageDialog(null, PRIVATE_KEY_ACCESS_FAILURE, PROBLEM, JOptionPane.WARNING_MESSAGE);
        }
        return privateKey;
    }

    /**
     * @return Obtém o {@link X509Certificate} da identidade selecionada
     */
    public X509Certificate getSignerCertificate() {
        if (!this.smartCardRepository.isIdentitySelected()) {
            this.smartCardRepository.showIdentitySelection();
        }

        X509Certificate signerCertificate = null;
        try {
            signerCertificate = (X509Certificate) this.smartCardRepository.getKeyStore()
                    .getCertificate(this.smartCardRepository.getAlias());

        } catch (KeyStoreException e) {
            Application.logger.log(Level.SEVERE, SIGNER_CERTIFICATE_ACCESS_PROBLEM, e);
            JOptionPane
                    .showMessageDialog(null, SIGNER_CERTIFICATE_ACCESS_PROBLEM, PROBLEM, JOptionPane.WARNING_MESSAGE);
        }
        return signerCertificate;
    }

	@Override
	public X509Certificate getCertificate() {
        if (!this.smartCardRepository.isIdentitySelected()) {
            this.smartCardRepository.showIdentitySelection();
        }

        X509Certificate signerCertificate = null;
        try {
            signerCertificate = (X509Certificate) this.smartCardRepository.getKeyStore()
                    .getCertificate(this.smartCardRepository.getAlias());

        } catch (KeyStoreException e) {
            Application.logger.log(Level.SEVERE, SIGNER_CERTIFICATE_ACCESS_PROBLEM, e);
            JOptionPane
                    .showMessageDialog(null, SIGNER_CERTIFICATE_ACCESS_PROBLEM, PROBLEM, JOptionPane.WARNING_MESSAGE);
        }
        return signerCertificate;
	}

}
