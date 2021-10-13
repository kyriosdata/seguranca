package br.ufsc.labsec.signature.repository.windows;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateCollection;

/**
 * Implementação de coleção de certificados que tem acesso aos certificados do
 * repositorio implementado pelo sistema operacional windows.
 */
public class WindowsCertificateCollection implements CertificateCollection {

    private WindowsRepository smartCardRepository;

    /**
     * Inicializa a coleção de certificados
     * 
     * @param windowsRepository Instância da classe que representa o componente
     *            WindowsRepository
     */
    public WindowsCertificateCollection(WindowsRepository windowsRepository) {
        this.smartCardRepository = windowsRepository;
    }

    @Override
    public Certificate getCertificate(CertSelector certSelector) {
        Collection<Certificate> certificates = null;
        try {
            certificates = (Collection<Certificate>) this.smartCardRepository.getCertStore().getCertificates(certSelector);
        } catch (CertStoreException e) {
            Application.logger.log(Level.SEVERE, "Não foi possível obter o certificado identificado pelo CertSelector", e);
        }
        if (certificates != null && certificates.size() > 0) {
            return certificates.iterator().next();
        } else {
            return null;
        }
    }

    @Override
    public void addCertificates(List<X509Certificate> certificates) {
        if (certificates != null) {
            List<Certificate> certList = this.getCertificateList();

            for (Certificate certificate : certificates) {
				if(!certList.contains(certificate))
					certList.add(certificate);
			}

            CollectionCertStoreParameters parameters = new CollectionCertStoreParameters(certList);
            try {
                this.smartCardRepository.setCertStore(CertStore.getInstance("Collection", parameters));
            } catch (InvalidAlgorithmParameterException e) {
                Application.logger.log(Level.SEVERE, "Algoritmo inválido usado na inserção de certificado", e);
            } catch (NoSuchAlgorithmException e) {
                Application.logger.log(Level.SEVERE, "Algoritmo inexistente usado na inserção de certificado", e);
            }
        }
    }

    /**
     * @return Lista de todos os certificados contidos no {@link CertStore} do
     *         {@link WindowsRepository}
     */
    @Override
    public List<Certificate> getCertificateList() {
        Collection<? extends Certificate> certCollection = null;
        List<Certificate> certList = new ArrayList<Certificate>();
        try {
            certCollection = this.smartCardRepository.getCertStore().getCertificates(new X509CertSelector());
        } catch (CertStoreException e) {
            Application.logger.log(Level.SEVERE, "Erro de acesso ao cert store", e);
        }

        if (certCollection != null) {

            certList.addAll(certCollection);
        }

        return certList;
    }

    @Override
    public X509Certificate getIssuerCertificate(X509Certificate certificate) {
        return null;
    }

}
