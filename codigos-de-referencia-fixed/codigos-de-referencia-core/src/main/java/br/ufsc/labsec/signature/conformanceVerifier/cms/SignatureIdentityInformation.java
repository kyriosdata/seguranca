package br.ufsc.labsec.signature.conformanceVerifier.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.RevocationInformation;

/**
 * Esta classe gerencia as listas de certificados e CRLs de uma assinatura CMS.
 * Implementa {@link RevocationInformation} e {@link CertificateCollection}.
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
public class SignatureIdentityInformation implements RevocationInformation, CertificateCollection {

	/**
	 * Lista de certificados usados na assinatura
	 */
	private Set<X509Certificate> certificates;
	/**
	 * Lista de Certificados Revogados
	 */
	private Set<X509CRL> crls;
	/**
	 * Componente de assinatura CMS
	 */
	private CmsSignatureComponent cmsSignatureComponent;

	/**
	 *  Construtor da classe
	 * @param cmsSignatureComponent Um componente de assinatura CMS
	 */
	public SignatureIdentityInformation(CmsSignatureComponent cmsSignatureComponent) {
		this.certificates = new HashSet<X509Certificate>();
		this.crls = new HashSet<X509CRL>();
		this.cmsSignatureComponent = cmsSignatureComponent;
	}

	/**
	 * Implementação de um {@link Selector}
	 */
	private static class SelectorCert implements Selector {

		@Override
		public boolean match(Object arg0) {
			return true;
		}

		@Override
		public Selector clone() {
			return new SelectorCert();
		}

	}

	/**
	 * Busca por um certificado entre a lista de certificados da assinatura
	 * @param certSelector Selector para identificar o certificado desejado
	 * @return O certificado desejado, ou nulo caso não seja encontrado
	 */
	@Override
	public Certificate getCertificate(CertSelector certSelector) {

		/*
		 * Naive optimization since retrieveCertificatesFromSignatureContainer
		 * would read a list of certificates from signature structure on every
		 * getCertificate call without this loop, making the whole process very
		 * slow.
		 */

		for (X509Certificate x509Certificate : this.certificates) {
			if (certSelector.match(x509Certificate)) {
				return x509Certificate;
			}
		}

		this.retrieveCertificatesFromSignatureContainer();

		for (X509Certificate x509Certificate : this.certificates) {
			if (certSelector.match(x509Certificate)) {
				return x509Certificate;
			}
		}

		return null;

	}

	/**
	 * Adiciona os certificados à lista de certificados da assinatura
	 * @param certificates Lista de certificados a serem adicionados
	 */
	@Override
	public void addCertificates(List<X509Certificate> certificates) {

		for (X509Certificate cert : certificates) {
			if (!this.certificates.contains(cert)) {
				this.certificates.add(cert);
			}
		}

	}

	/**
	 * Busca a CRL de um certificado
	 * @param certificate Certificado que se deseja a CRL
	 * @param timeReference Data da CRL desejada
	 * @return A CRL desejada, ou nulo caso não seja encontrada
	 */
	@Override
	public CRLResult getCRLFromCertificate(Certificate certificate, Time timeReference) {

		this.retrieveCrlsFromSignatureContainer();

		for (X509CRL x509crl : this.crls) {
			X509Certificate xCert = (X509Certificate) certificate;
			if (xCert.getIssuerX500Principal().equals(x509crl.getIssuerX500Principal())) {
				if (x509crl.getThisUpdate().compareTo(timeReference) >= 0
						&& x509crl.getNextUpdate().compareTo(timeReference) < 0) {
					CRLResult result = new CRLResult();
					result.crl = x509crl;
					result.fromWeb = false;
					return result;
				}
			}
		}

		return null;

	}

	/**
	 * Retorna a lista de certificados utilizados na assinatura
	 * @return Lista de certificados da assinatura
	 */
	@Override
	public List<Certificate> getCertificateList() {
		this.retrieveCertificatesFromSignatureContainer();
		return new ArrayList<Certificate>(this.certificates);
	}

	@Override
	public X509Certificate getIssuerCertificate(X509Certificate certificate) {
		return null;
	}

	/**
	 * Adiciona uma CRL à lista de certificados revogados
	 * @param certValuesCertificates Lista de certificados aos quais pertencem as CRLs
	 * @param crlsList A lista de CRLs a ser adicionada
	 */
	@Override
	public void addCrl(List<X509Certificate> certValuesCertificates, List<X509CRL> crlsList) {
		this.crls.addAll(crlsList);
	}

	/**
	 * Busca os certificados usados na assinatura no componente de assinatura CMS
	 */
	private void retrieveCertificatesFromSignatureContainer() {

		CmsSignatureContainer sigContainer = this.cmsSignatureComponent.getVerifier().getSignatureContainer();

		if (sigContainer != null) {

			Store certStore = sigContainer.getCertificateStore();
			Selector selector = new SelectorCert();
			Collection<X509CertificateHolder> collection = certStore.getMatches(selector);
	
			ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
	
			try {
				CertificateFactory certificateFac = CertificateFactory.getInstance("X.509");
	
				for (X509CertificateHolder certHolder : collection) {
					certificates.add((X509Certificate) certificateFac
							.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded())));
				}
	
			} catch (CertificateException | IOException e) {
				Application.logger.log(Level.SEVERE, "Não foi possível decodificar o certificado do assinante.", e);
				return;
			}
	
			this.certificates.addAll(certificates);
		}

	}

	/**
	 * Busca a lista de certificados revogados no componente de assinatura CMS
	 */
	private void retrieveCrlsFromSignatureContainer() {

		CmsSignatureContainer sigContainer = this.cmsSignatureComponent.getVerifier().getSignatureContainer();
		if(sigContainer != null) {
			Store crlStore = sigContainer.getCrls();
			Selector selector = new SelectorCert();
			Collection<X509CRLHolder> collection = crlStore.getMatches(selector);
	
			ArrayList<X509CRL> crls = new ArrayList<X509CRL>();
			JcaX509CRLConverter converter = new JcaX509CRLConverter();
	
			try {
				for (X509CRLHolder crlHolder : collection) {
					crls.add((X509CRL) converter.getCRL(crlHolder));
				}
			} catch (CRLException e) {
				Application.logger.log(Level.SEVERE, "Não foi possível decodificar a LCR.", e);
			}
	
			this.crls.addAll(crls);
		}
	}

}