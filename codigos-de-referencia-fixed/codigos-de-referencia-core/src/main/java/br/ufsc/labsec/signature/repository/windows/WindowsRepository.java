package br.ufsc.labsec.signature.repository.windows;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.IdentityConfirmer;
import br.ufsc.labsec.signature.IdentitySelector;
import br.ufsc.labsec.signature.PrivateInformation;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.repository.PKCS12IdentityService.CRLCacheManagement;
import br.ufsc.labsec.signature.repository.PKCS12IdentityService.OCSPClient;

/**
 * Classe que representa o componente que fornece acesso aos certificados do
 * repositório do Windows
 */
public class WindowsRepository extends Component {

    private static final String KEYSTORE_INICIALIZATION_FAILURE = "Não foi possível inicializar o repositório de certificados.";

    private static final String CERTSTORE_CONSTRUCTION_FAILURE = "Não foi possível instânciar o certStore.";

    @Requirement (optional = true)
    public IdentityConfirmer identityConfirmer; 
    @Requirement
    public List<CertificateCollection> aditionalCertificateCollection;
    @Requirement
    public List<RevocationInformation> aditionalRevocationInformation;
    
    private WindowsCertificateCollection certificateCollection;
    private WindowsPrivateInformation privateInformation;
    private WindowsIdentitySelector identitySelector;
    private RevocationInformation ocspClient;
    private RevocationInformation crlCacheManagement;
    private KeyStore keyStore;

    private CertStore certStore;

    /**
     * Instancia os provedores de serviço do componente e prepara o
     * {@link Application}
     * 
     * @param application A instância da {@link Application} que contém os
     *            componentes
     */
    public WindowsRepository(Application application) {
        super(application);

        this.setupKeyStore();

        this.defineRoleProvider(PrivateInformation.class.getName(), this.getPrivateInformation());
        this.defineRoleProvider(CertificateCollection.class.getName(), this.getCertificateCollection());
        this.defineRoleProvider(IdentitySelector.class.getName(), this.getIdentitySelector());
        this.defineRoleProvider(RevocationInformation.class.getName(), this.getOCSPClient());
        this.defineRoleProvider(RevocationInformation.class.getName(), this.getCrlCacheManagement());
        
    }

    /**
     * Inicializa o {@link KeyStore} que fornece o acesso aos certificados do
     * repositório do Windows. Para acessar os certificados intermediários
     * também é instânciado um {@link CertStore}.
     */
    private void setupKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance("Windows-MY");
            this.keyStore.load(null, null);
        } catch (KeyStoreException e) {
            Application.logger.log(Level.SEVERE, KEYSTORE_INICIALIZATION_FAILURE, e);
        } catch (NoSuchAlgorithmException e) {
            Application.logger.log(Level.SEVERE, KEYSTORE_INICIALIZATION_FAILURE, e);
        } catch (CertificateException e) {
            Application.logger.log(Level.SEVERE, KEYSTORE_INICIALIZATION_FAILURE, e);
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, KEYSTORE_INICIALIZATION_FAILURE, e);
        }

        this.setupCertStore();
    }

    /**
     * Instancia um {@link CertStore} a partir do {@link KeyStore} inicializado
     * com os certificados do repositório do Windows.
     */
    private void setupCertStore() {
        if (this.keyStore != null) {
            List<Certificate> certificates = new ArrayList<Certificate>();
            Enumeration<String> aliases = null;
            try {
                aliases = this.keyStore.aliases();
            } catch (KeyStoreException e) {
                Application.logger.log(Level.SEVERE, "Não foi possível obter os nomes dos certificados no repositório.", e);
            }
            if (aliases != null) {
                obtainCertificates(certificates, aliases);
            }

            CollectionCertStoreParameters parameters = new CollectionCertStoreParameters(certificates);
            try {
                this.certStore = CertStore.getInstance("Collection", parameters);
            } catch (InvalidAlgorithmParameterException e) {
                Application.logger.log(Level.SEVERE, CERTSTORE_CONSTRUCTION_FAILURE, e);
            } catch (NoSuchAlgorithmException e) {
                Application.logger.log(Level.SEVERE, CERTSTORE_CONSTRUCTION_FAILURE, e);
            }
        }
    }

    /**
     * Extrai as cadeias de certificação para os aliases passados.
     * 
     * @param certificates Lista onde os certificados serão armazenados
     * @param aliases Aliases que indicam os certificados disponíveis no
     *            repositório
     */
    private void obtainCertificates(List<Certificate> certificates, Enumeration<String> aliases) {
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate[] chain = null;
            try {
                chain = this.keyStore.getCertificateChain(alias);
            } catch (KeyStoreException e) {
                Application.logger.log(Level.SEVERE,
                        "Não foi possível obter a cadeia de certificação do certificado nomeado por: " + alias, e);
            }
            if (chain != null) {
                certificates.addAll(Arrays.asList(chain));
            }
        }
    }

    /**
     * @return Provedor de serviços para a interface
     *         {@link CertificateCollection}
     */
    WindowsCertificateCollection getCertificateCollection() {
        if (this.certificateCollection == null) {
            this.certificateCollection = new WindowsCertificateCollection(this);
        }
        return this.certificateCollection;
    }

    /**
     * @return Provedor de serviços para a interface {@link PrivateInformation}
     */
    private WindowsPrivateInformation getPrivateInformation() {
        if (this.privateInformation == null) {
            this.privateInformation = new WindowsPrivateInformation(this);
        }
        return this.privateInformation;
    }

    /**
     * @return Provedor de serviços para interface {@link IdentitySelector}
     */
    private WindowsIdentitySelector getIdentitySelector() {
        if (this.identitySelector == null) {
            this.identitySelector = new WindowsIdentitySelector(this);
        }
        return this.identitySelector;
    }

    @Override
    public void startOperation() {

    }

    /**
     * @return Obtém o KeyStore que tem acesso as informações privadas do
     *         Windows repository.
     */
    public KeyStore getKeyStore() {
        return this.keyStore;
    }

    /**
     * Callback para o login do usuário
     */
    public void showIdentitySelection() {
    	this.identityConfirmer.askIdentity();
    }

    /**
     * @return True se alguma identidade já foi selecionada.
     */
    public boolean isIdentitySelected() {
        return this.identitySelector.isIdentitySelected();
    }

    /**
     * @return O nome identificador da identidade selecionada
     */
    public String getAlias() {
        return this.identitySelector.getSelectedIdentity();
    }

    /**
     * Reinstancia o {@link KeyStore} para que a identidade seja desselecionada
     */
    public void reloadKeyStore() {
        this.setupKeyStore();
    }
    
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

    @Override
    public void clear() {
        // TODO Auto-generated method stub

    }

    /**
     * @param newCertStore A nova instância do CertStore a ser considerado
     */
    public void setCertStore(CertStore newCertStore) {
        this.certStore = newCertStore;
    }

    /**
     * @return A instância atual do certStore com os certificados intermediários
     *         e finais
     */
    public CertStore getCertStore() {
        return this.certStore;
    }

    /**
     * @return O endereço onde o cachePath
     */
    public String getCachePath() {
        return this.getApplication().getComponentParam(this, "cachePath");
    }

}
