package br.ufsc.labsec.signature.repository.PKCS12IdentityService;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.logging.Level;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileFilter;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.IdentityConfirmer;
import br.ufsc.labsec.signature.IdentitySelector;
import br.ufsc.labsec.signature.PrivateInformation;
import br.ufsc.labsec.signature.RevocationInformation;

/**
 * Componente Repositorio PKCS12
 * 
 */
public class PKCS12Repository extends Component {

	@Requirement (optional = true)
	public List<CertificateCollection> aditionalCertificateCollection;
	@Requirement (optional = true)
	public List<RevocationInformation> aditionalRevocationInformation;
	@Requirement (optional = true)
	public IdentityConfirmer identityConfirmer;

	private PrivateInformation privateInformation;
	private PKCS12CertificateColletionImpl certificateCollection;
	private RevocationInformation ocspClient;
	private RevocationInformation crlCacheManagement;

	private String pkcs12Path;
	private KeyStore keyStore;

	private IdentitySelector identitySelector;

	/**
	 * Cria o componente PKCS12
	 * 
	 * @param application
	 *            Aplicativo
	 */
	public PKCS12Repository(Application application) {
		super(application);

		this.defineRoleProvider(IdentitySelector.class.getName(), this.getIdentitySelector());
		this.defineRoleProvider(PrivateInformation.class.getName(), this.getPrivateInformation());
		this.defineRoleProvider(RevocationInformation.class.getName(), this.getOCSPClient());
		this.defineRoleProvider(RevocationInformation.class.getName(), this.getCrlCacheManagement());
		this.defineRoleProvider(CertificateCollection.class.getName(), this.getCertificateCollection());

	}

	private IdentitySelector getIdentitySelector() {
		if (this.identitySelector == null) {
			this.identitySelector = new PKCS12IdentitySelector(this);
		}
		return this.identitySelector;
	}

	/**
	 * Retorna PrivateInformation
	 * 
	 * @return PrivateInformation
	 */
	private PrivateInformation getPrivateInformation() {
		if (this.privateInformation == null) {
			this.privateInformation = new PKCS12PrivateInformationImpl(this);
		}
		return this.privateInformation;
	}

	/**
	 * Retorna o caminho do repositorio
	 * 
	 * @return O caminho do repositorio
	 */
	public String getRepositoryPath() {

		return this.application.getComponentParam(this, "repositoryPath");
	}

	/**
	 * Retorna RevocationInformation OCSP
	 * 
	 * @return RevocationInformation OCSP
	 */
	private RevocationInformation getOCSPClient() {
		if (this.ocspClient == null) {
			this.ocspClient = new OCSPClient();
		}
		return this.ocspClient;
	}

	/**
	 * Retorna RevocationInformation CRL
	 * 
	 * @return RevocationInformation CRL
	 */
	private RevocationInformation getCrlCacheManagement() {
		if (this.crlCacheManagement == null) {
			this.crlCacheManagement = new CRLCacheManagement(this.getCachePath());
		}
		return this.crlCacheManagement;
	}

	/**
	 * Retorna PKCS12CertificateColletionImpl
	 * 
	 * @return PKCS12CertificateColletionImpl
	 */
	public PKCS12CertificateColletionImpl getCertificateCollection() {
		if (this.certificateCollection == null) {
			this.certificateCollection = new PKCS12CertificateColletionImpl(
					this);
		}

		return this.certificateCollection;
	}

	@Override
	public void startOperation() {
		// TODO Auto-generated method stub

	}

	@Override
	public void clear() {
		this.keyStore = null;

	}

	/**
	 * Retorna o caminho do arquivo de cache.
	 * 
	 * @return O cache.
	 */
	public String getCachePath() {
		return this.application.getComponentParam(this, "cachePath");
	}

	public boolean isIdentitySelected() {
		return this.identitySelector.isIdentitySelected();
	}

	public void showIdentitySelection() {
		this.identityConfirmer.askIdentity();
	}

	public void reloadPkcs12(char[] password) {
		try {
			this.keyStore = KeyStore.getInstance("PKCS12");
			this.keyStore.load(new FileInputStream(this.pkcs12Path), password);
		} catch (KeyStoreException e) {
			Application.logger.log(Level.SEVERE,
					"Não foi possível recarregar o PKCS#12", e);
		} catch (NoSuchAlgorithmException e) {
			Application.logger.log(Level.SEVERE,
					"Não foi possível recarregar o PKCS#12", e);
		} catch (CertificateException e) {
			Application.logger.log(Level.SEVERE,
					"Não foi possível recarregar o PKCS#12", e);
		} catch (FileNotFoundException e) {
			Application.logger.log(Level.SEVERE,
					"Não foi possível recarregar o PKCS#12", e);
		} catch (IOException e) {
//			Application.logger.log(Level.SEVERE,
//					"Não foi possível recarregar o PKCS#12", e);
		}
	}

	public KeyStore getPkcs12() {
		if (this.keyStore == null) {
			this.setupPkcs12();
		}
		return this.keyStore;
	}

	public String getAlias() {
		return this.identitySelector.getSelectedIdentity();
	}

	public void setupPkcs12() {
		if (this.application.getParameter("pkcs12") == null || pkcs12Path.equals(null)) {
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setAcceptAllFileFilterUsed(false);
			fileChooser.setDialogTitle("Arquivo de chaves e certificados");
			fileChooser.addChoosableFileFilter(new FileFilter() {

				@Override
				public String getDescription() {
					return "Arquivo PKCS#12";
				}

				@Override
				public boolean accept(File file) {
					return file.getName().endsWith(".p12")
							|| file.isDirectory();
				}
			});
			while (this.keyStore == null) {
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					this.pkcs12Path = fileChooser.getSelectedFile()
							.getAbsolutePath();
					this.loadPkcs12();
				} else {
					if (JOptionPane
							.showConfirmDialog(
									null,
									"Não é possível operar sem um arquivo PKCS#12.\nDeseja tentar selecionar um novamente?",
									"Problema", JOptionPane.YES_NO_OPTION) == JOptionPane.NO_OPTION) {
						break;
					}
				}
			}
		} else {
			this.pkcs12Path = this.application.getParameter("pkcs12");
			this.loadPkcs12();
		}

	}

	private void loadPkcs12() {
		try {
			this.keyStore = KeyStore.getInstance("PKCS12");
			this.keyStore.load(new FileInputStream(this.pkcs12Path), null);
		} catch (NoSuchAlgorithmException e) {
			Application.logger.log(Level.SEVERE, "", e);
		} catch (CertificateException e) {
			Application.logger.log(Level.SEVERE, "", e);
		} catch (FileNotFoundException e) {
			Application.logger.log(Level.SEVERE, "", e);
		} catch (IOException e) {
			Application.logger.log(Level.SEVERE, "", e);
		} catch (KeyStoreException e) {
			Application.logger.log(Level.SEVERE, "", e);
		}
	}
}
