/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdCounterSignature;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma assinatura CMS qualquer que contém,no mínimo, o atributo
 * {@link IdAaEtsSigPolicyId}. Estende {@link CadesSignatureInformation}.
 */
public class CadesSignature extends CadesSignatureInformation {

	/**
	 * Contêiner de assinatura CAdES
	 */
    protected CadesSignatureContainer cadesSignatureContainer;
	/**
	 * Tipo do conteúdo assinado
	 */
	protected String eContentType;

    /**
     * Cria uma assinatura CAdES
     * @param cadesSignatureContainer Contêiner ao qual a assinatura está
     *            inserida
     * @param signerInformation O {@link SignerInformation} do assinante ao qual
     *            se deseja obter a assinatura
     * @param parent Representação do "pai" da assinatura que deseja ser
     *            obtida
     * @throws EncodingException Exceção caso a assinatura não for codificada corretamente
     */
	public CadesSignature(CadesSignatureContainer cadesSignatureContainer, SignerInformation signerInformation, CmsParent parent)
        throws EncodingException {
        super(signerInformation, cadesSignatureContainer.hasDetachedContent(), parent);
        this.cadesSignatureContainer = cadesSignatureContainer;
        this.eContentType = cadesSignatureContainer.getEContentType();
    }

    /**
     * Obtém o valor do campo <code>eContentType</code>.
     * @return O valor do atributo <code>eContentType</code>.
     */
    public String getEContentType() {
        return eContentType;
    }

    /**
     * Obtém o contêiner ao qual a assinatura pertence
     * @return O contêiner da assinatura
     */
    public CadesSignatureContainer getCadesSignatureContainer() {
        return cadesSignatureContainer;
    }

	/**
	 * Adiciona um atributo não-assinado
	 * @param attribute O atributo a ser adicionado na assintura
	 * @throws PbadException Exceção em caso de erro na adição do atributo
	 * @throws SignatureAttributeException Exceção em caso de erro no atributo
	 */
    @Override
    public void addUnsignedAttribute(SignatureAttribute attribute) throws PbadException, SignatureAttributeException {
        super.addUnsignedAttribute(attribute);
    }

	/**
	 * Adiciona uma contra-assinatura
	 * @param counterSignatureAttribute O atributo da contra-assinatura
	 */
    @Override
    public void addCounterSignature(IdCounterSignature counterSignatureAttribute) {
        super.addCounterSignature(counterSignatureAttribute);
    }

    /**
     * Esse método deve ser usado quando uma contra-assinatura sofre alguma
     * alteração (por exemplo: adição de um novo atributo não assinado), assim a
     * assinatura que contém a contra assinatura deverá utilizar este método
     * @param counterSignatureAttribute A contra-assinatura a ser atualizada
     */
    public void replaceCounterSignature(IdCounterSignature counterSignatureAttribute) {
        super.replaceChildSignature(((IdCounterSignature) counterSignatureAttribute).getSignerInformation());
    }

	/**
	 * Retorna os certificados da assinatura
	 * @return Os certificados da assinatura
	 */
    public List<X509Certificate> getCertificates() throws CertificateException, IOException {
        Store certStore = this.cadesSignatureContainer.cmsSignedData.getCertificates();
        Selector selector = new SelectorCert();
        Collection<X509CertificateHolder> collection = certStore.getMatches(selector);
        CertificateFactory certificateFac = CertificateFactory.getInstance("X509");

        ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();

        for (X509CertificateHolder x509CertificateHolder : collection) {
            certificates.add((X509Certificate) certificateFac.generateCertificate(new ByteArrayInputStream(x509CertificateHolder
                    .getEncoded())));
        }

        return certificates;
    }

	/**
	 * Retorna o certificado do assinante contido no atributo da assinatura
	 * @return O certificado do assinante
	 * @throws SignatureAttributeException Exceção em caso de erro no atributo do certificado
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws IOException Exceção em caso de erro na obtenção do certificado
	 */
	public X509Certificate getSigningCertificate()
			throws SignatureAttributeException, CertificateException, IOException {

		SigningCertificateInterface signingCertificate = null;
		List<String> attrList = this.getAttributeList();

		if (!attrList.isEmpty()) {
			if (attrList.contains(IdAaSigningCertificate.IDENTIFIER)) {
				signingCertificate = new IdAaSigningCertificate(
						this.getEncodedAttribute(IdAaSigningCertificate.IDENTIFIER));
			} else {
				signingCertificate = new IdAaSigningCertificateV2(
						this.getEncodedAttribute(IdAaSigningCertificateV2.IDENTIFIER));
			}

			for (X509Certificate cert : this.getCertificates()) {
				if (signingCertificate.match(cert)) {
					return cert;
				}
			}
		}

		return null;

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
	 * Retorna as CRLs da assinatura
	 * @return As CRLs da assinatura
	 * @throws CRLException Exceção em caso de erro na manipulação das CRLs
	 */
    public List<X509CRL> getCrls() throws CRLException { 
    	Store crlStore = this.cadesSignatureContainer.cmsSignedData.getCRLs(); 
    	Selector selector = new SelectorCert();
    	Collection<X509CRLHolder> collection = crlStore.getMatches(selector); 
    	JcaX509CRLConverter crlConverter = new JcaX509CRLConverter().setProvider("BC"); 
	    
    	List<X509CRL> crls = new ArrayList<X509CRL>(); 
     	
    	for (X509CRLHolder x509CRLHolder : collection) { 
    		crls.add((X509CRL) crlConverter.getCRL(x509CRLHolder)); 
     	} 
     	
    	return crls; 
	 } 

}
