package br.ufsc.labsec.signature.conformanceVerifier.xades;

import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertValuesException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import org.w3c.dom.Element;

import java.security.cert.*;
import java.sql.Time;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Esta classe gerencia as listas de certificados e CRLs de uma assinatura XAdES.
 * Implementa {@link RevocationInformation} e {@link CertificateCollection}.
 */

public class SignatureIdentityInformation implements RevocationInformation, CertificateCollection {

	/**
	 * Lista de certificados usados na assinatura
	 */
	private List<X509Certificate> certificates;
	/**
	 * Lista de Certificados Revogados
	 */
	private List<X509CRL> crls;
	/**
	 * Componente de assinatura XAdES
	 */
    private XadesSignatureComponent xadesSignatureComponent;

	/**
	 *  Construtor da classe
	 * @param xadesSignature Um componente de assinatura XAdES
	 */
    public SignatureIdentityInformation(XadesSignatureComponent xadesSignature) {
    	this.certificates = new ArrayList<X509Certificate>();
    	this.crls = new ArrayList<X509CRL>();
        this.xadesSignatureComponent = xadesSignature;
    }

	/**
	 * Busca por um certificado entre a lista de certificados da assinatura
	 * @param certSelector Selector para identificar o certificado desejado
	 * @return O certificado desejado, ou nulo caso não seja encontrado
	 */
    @Override
    public Certificate getCertificate(CertSelector certSelector) {
    	
     	for (X509Certificate x509Certificate : this.certificates) {
			if(certSelector.match(x509Certificate))
				return x509Certificate;
		}
    	
    	 XadesSignature xadesSignature = xadesSignatureComponent.getVerifier().getSelectedSignature();
         List<X509Certificate> certValueslist = null;
         List<X509Certificate> xadesCertlist = null;
         List<X509Certificate> list = new ArrayList<X509Certificate>();

         if(xadesSignature == null) 
         	return null;
         
         if(xadesSignature.getAttributeList().contains(CertificateValues.IDENTIFIER)) {
         
	         Element attribute = null;
	         try {
	             attribute = xadesSignature.getEncodedAttribute(CertificateValues.IDENTIFIER);
	         } catch (SignatureAttributeNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	
	         try {
	        	 CertificateValues certValues = new CertificateValues(attribute);
	             certValueslist = certValues.getCertValues();
	
	         } catch (EncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertValuesException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	
	         xadesCertlist = xadesSignature.getCertificatesAtKeyInfo();
	
	         if (xadesCertlist != null)
		        	this.addAllCertificate(list, xadesCertlist);
		     if (certValueslist != null)
		        this.addAllCertificate(list, certValueslist);
         }
         
         if (certificates != null)
         	this.addAllCertificate(list, certificates);

		for (X509Certificate x509Certificate : list)
			if (certSelector.match(x509Certificate))
				return x509Certificate;

        
        return null;
    }

	/**
	 * Adiciona os certificados à lista de certificados da assinatura
	 * @param certificates Lista de certificados a serem adicionados
	 */
    @Override
	public void addCertificates(List<X509Certificate> certificates) {
    	this.addAllCertificate(this.certificates, certificates);
	}

	/**
	 * Busca a CRL de um certificado
	 * @param certificate Certificado que se deseja a CRL
	 * @param timeReference Data da CRL desejada
	 * @return A CRL desejada, ou nulo caso não seja encontrada
	 */
	@Override
    public CRLResult getCRLFromCertificate(Certificate certificate, Time timeReference) {
    	XadesSignature xadesSignature = xadesSignatureComponent.getVerifier().getSelectedSignature();
    	
    	if(xadesSignature == null)
    		return null;
    	
    	List<X509CRL> crlValueslist = null;
    	List<X509CRL> cadesCrllist = null;
    	List<X509CRL> list = new ArrayList<X509CRL>();
    	
    	if(xadesSignature.getAttributeList().contains(RevocationValues.IDENTIFIER)) {
    	
	        try {
	        	 Element attribute = xadesSignature.getEncodedAttribute(RevocationValues.IDENTIFIER);
	        	 RevocationValues revocationValues = new RevocationValues(attribute);
	             crlValueslist = revocationValues.getCrlValues();
	             
	             cadesCrllist = xadesSignature.getCrls();
	             
	         } catch (CRLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureAttributeNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureAttributeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	        
	        if (crlValueslist != null)
	            this.addAllCrl(list, crlValueslist);
	        if (cadesCrllist != null)
	            this.addAllCrl(list, cadesCrllist);
    	}
        
    	this.addAllCrl(list, crls);

        for (X509CRL x509crl : list) {
            X509Certificate xCert = (X509Certificate) certificate;
            boolean sameIssuer = xCert.getIssuerX500Principal()
                    .equals(x509crl.getIssuerX500Principal());
            boolean beforeNextUpdate = timeReference.before(x509crl.getNextUpdate());
            boolean afterThisUpdate = timeReference.after(x509crl.getThisUpdate());

            if (sameIssuer && beforeNextUpdate && afterThisUpdate) {
                CRLResult result = new CRLResult();
                result.crl = x509crl;
                result.fromWeb = false;
                return result;
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
        XadesSignature xadesSignature = xadesSignatureComponent.getVerifier().getSelectedSignature();
        if (xadesSignature != null) {
            List<X509Certificate> xadesCertlist = null;
            List<Certificate> certList = new ArrayList<Certificate>();

            xadesCertlist = xadesSignature.getCertificatesAtKeyInfo();

			for (X509Certificate x509Certificate : xadesCertlist) {
				if (!certList.contains(x509Certificate))
					certList.add((Certificate) x509Certificate);
			}

			for (X509Certificate certificate : certificates) {
				if (!certList.contains(certificate))
					certList.add(certificate);
			}
           

            return certList;
        } else {
			List<Certificate> certs = new ArrayList<Certificate>(this.certificates);
            return certs;
        }
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
	 * Adiciona as entradas de uma lista à outra lista dada sem repetições
	 * @param dest A lista de CRLs que receberá os valores, sem repetições
	 * @param source A lista de CRLs cujos valores serão copiados
	 */
	private void addAllCrl(List<X509CRL> dest, List<X509CRL> source) {
    	for (X509CRL x509Crl : source) {
			if(!dest.contains(x509Crl))
				dest.add(x509Crl);
		}
    }

	/**
	 * Adiciona as entradas de uma lista à outra lista dada sem repetições
	 * @param dest A lista de certificados que receberá os valores, sem repetições
	 * @param source A lista de certificados cujos valores serão copiados
	 */
    private void addAllCertificate(List<X509Certificate> dest, List<X509Certificate> source) {
    	for (X509Certificate x509Certificate : source) {
			if(!dest.contains(x509Certificate))
				dest.add(x509Certificate);
		}
    }

	/**
	 * Busca por uma CRL entre a lista de CRLs da assinatura
	 * @param selector Selector para identificar a CRL desejada
	 * @param timeReference Data de referência na qual a CRL deve ser válida
	 * @return A CRL desejada, ou uma lista vazia caso não seja encontrada
	 */
	public List<X509CRL> getCRLs(X509CRLSelector selector, Time timeReference) {
		Set<X509CRL> crlsRet = new HashSet<>();

		for (X509CRL crl : this.crls) {
			if (selector.match(crl) && crl.getNextUpdate().after(timeReference)
					&& crl.getThisUpdate().before(timeReference)) {
				crlsRet.add(crl);
			}
		}

		return new ArrayList<>(crlsRet);
	}
    
}
