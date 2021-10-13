/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;

import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.MandatedCertRefException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SigningCertificateException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.TACException;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertRefReq;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

//import br.ufsc.labsec.pbad.policies.SignerRules.CertRefReq;

/**
 * O atributo IdAaSigningCertificate é designado para previnir o ataque de
 * substituição, e para permitir um conjunto restrito de certificados a serem
 * usados na verificação da assinatura.
 * <p>
 * Este atributo é obrigatório para todas as políticas do Padrão Brasileiro de
 * Assinatura Digital.
 * <p>
 * Esta versão representa uma referência do certificado do signatário utilizando
 * o algoritmo de hash SHA1.
 * <p>
 * 
 * <pre>
 * SigningCertificate ::= SEQUENCE {
 * certs SEQUENCE OF ESSCertID,
 * policies SEQUENCE OF PolicyInformation OPTIONAL
 * }
 * </pre>
 * 
 * @see <a href="http://tools.ietf.org/html/rfc5035">RFC 5035</a>
 */
public class IdAaSigningCertificate implements SigningCertificateInterface {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_signingCertificate.toString();
    /**
     * Lista de identificadores dos certificados
     */
    protected List<ESSCertID> certs;
    /**
     * Objeto de verificador
     */
    protected AbstractVerifier signatureVerifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo.
     * Este método decodifica todos os certificados que foram adicionados no
     * atributo SigningCertificate, ou seja, ele funciona para os casos
     * SignerOnly e FullPath.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Este índide deve ser 0 para este atributo
     * @throws SignatureAttributeException
     */
    public IdAaSigningCertificate(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = signatureVerifier;
        CadesSignature signature = this.signatureVerifier.getSignature();
        Attribute genericEncoding = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(genericEncoding);
    }

    /**
     * Cria o atributo id-aa-signingCertificate a partir de uma lista de
     * certificados. Este método decodifica todos os certificados que foram
     * adicionados no atributo SigningCertificate.
     * @param certs Lista de certificados que serão guardados no atributo
     *            signing certificate da assinatura
     * @throws SignatureAttributeException
     */
    public IdAaSigningCertificate(List<X509Certificate> certs) throws SignatureAttributeException {
        if (certs == null || certs.size() == 0) {
            throw new SignatureAttributeException(
                    "Para construção do id-aa-signingCertificate é necessário passar ao menos o certificado do assinante");
        }
        this.certs = new ArrayList<ESSCertID>();
        for (X509Certificate cert : certs) {
            byte[] certHash = this.getCertificateHash(cert);
            IssuerSerial issuerSerial = this.getIssuerSerial(cert.getIssuerX500Principal().toString(), cert.getSerialNumber());
            ESSCertID essCertId = new ESSCertID(certHash, issuerSerial);
            this.certs.add(essCertId);
        }
    }

    /**
     * Constrói um objeto {@link IdAaSigningCertificate}.
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaSigningCertificate(Attribute genericEncoding) throws SigningCertificateException {
        this.decode(genericEncoding);
    }

    /**
     * Constrói um objeto {@link IdAaSigningCertificate}.
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Attribute genericEncoding) throws SigningCertificateException {
        this.certs = new ArrayList<ESSCertID>();
        Attribute idAaSigningCertificateAttribute = null;
        // try{
        idAaSigningCertificateAttribute = genericEncoding;
        // }catch(EncodingException encodingException){
        // throw new SigningCertificateException(encodingException.getMessage(),
        // encodingException.getStackTrace());
        // }
        ASN1Object derObject = idAaSigningCertificateAttribute.toASN1Primitive();
        ASN1Sequence asn1Sequence = (ASN1Sequence) derObject;
        ASN1Set asn1Set = (ASN1Set) asn1Sequence.getObjectAt(1);
        ASN1Sequence signingCertificateSequence = (ASN1Sequence) asn1Set.getObjectAt(0);
        ASN1Sequence certsSequence = (ASN1Sequence) signingCertificateSequence.getObjectAt(0);
        for (int i = 0; i < certsSequence.size(); i++) {
            ASN1Sequence certIdSequence = (ASN1Sequence) certsSequence.getObjectAt(i);
            ESSCertID certID = ESSCertID.getInstance(certIdSequence);
            this.certs.add(certID);
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaSigningCertificate.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {

    	SignaturePolicyInterface signaturePolicy = this.signatureVerifier.getSignaturePolicy();
    	CertPath certPath = this.signatureVerifier.getCertPath();
    	
    	//verifica se é i, cadesVerifier
    	if(!this.signatureVerifier.isTimeStamp()){
	    
    		CertRefReq certRefReq = signaturePolicy.getSigningCertRefReq();
    		if (certRefReq != null && certRefReq.equals(CertRefReq.SIGNER_ONLY) && this.certs.size() != 1) {
	            // é signerOnly mas tem mais de um certificado
	            throw new SignatureAttributeException(MandatedCertRefException.ISNT_SIGNER_ONLY);
	        } else if (certRefReq.equals(CertRefReq.FULL_PATH)) {
	        
	        	if (this.certs.size() > 1) {
	                for (int i = 0; i <= this.certs.size(); i++) {
	                    X509Certificate cert = (X509Certificate) certPath.getCertificates().get(i);
	                    if (!this.certs.get(i).equals(this.getCertificateHash(cert))) {
	                        // nova exceção: os hashs dos certificados não batem
	                        throw new SignatureAttributeException(SigningCertificateException.INVALID_CERTIFICATE_HASH);
	                    }
	                }
	            } else {
	                // É fullPath mas só tem um certificado, ou nenhum
	                throw new SignatureAttributeException(MandatedCertRefException.ISNT_FULL_PATH);
	            }
	        }
    	//caso for um TSVerifier
    	}else{
    		if (this.certs.size() > 1) {
    			throw new TACException("O SigningCertificate contém referências não verificadas a certificados.");
//                for (int i = 0; i <= this.certs.size(); i++) {
//                    X509Certificate cert = (X509Certificate) certPath.getCertificates().get(i);
//                    if (!this.certs.get(i).equals(this.getCertificateHash(cert))) {
//                        // nova exceção: os hashs dos certificados não batem
//                        throw new SignatureAttributeException(SigningCertificateException.INVALID_CERTIFICATE_HASH);
//                    }
//                }
    			
    			
    		}
    	}
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN1
     */
    @Override
    public Attribute getEncoded() {
        ASN1EncodableVector certsEncoded = new ASN1EncodableVector();
        for (ESSCertID essCertID : this.certs) {
            //            ASN1EncodableVector essCertIDEncoded = this.encodeEssCertId(essCertID);
//            certsEncoded.add(new DERSequence(essCertIDEncoded));
            certsEncoded.add(essCertID);
        }
        ASN1EncodableVector encodedSigningCertificate = new ASN1EncodableVector();
        encodedSigningCertificate.add(new DERSequence(certsEncoded));
        DERSequence signingCertificateSequence = new DERSequence(encodedSigningCertificate);
        Attribute signingCertificateAttribute = new Attribute(new ASN1ObjectIdentifier(this.getIdentifier()), new DERSet(
                signingCertificateSequence));
        return signingCertificateAttribute;
    }

    /**
     * Informa se o atributo é assinado
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return true;
    }

    /**
     * Obtém todos os certificados que foram guardados no atributo signing
     * certificate da assinatura.
     * @return A lista dos certificados do atributo
     */
    public List<ESSCertID> getESSCertID() {
        return this.certs;
    }

    /**
     * Calcula o hash do certificado
     * @param certificate O certificado
     * @return O Hash do certificado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    private byte[] getCertificateHash(X509Certificate certificate) throws SignatureAttributeException {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureAttributeException(SigningCertificateException.NO_SUCH_ALGORITHM_EXCEPTION);
        }
        try {
            messageDigest.update(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new SignatureAttributeException(SigningCertificateException.CERTIFICATE_ENCODING_EXCEPTION);
        }
        return messageDigest.digest();
    }

    /**
     * Cria um objeto {@link IssuerSerial} com as informações dadas
     * @param issuerDirName Nome do emissor do certificado
     * @param subjectSerial Número de série do certificado emitido
     * @return O {@link IssuerSerial} criado
     */
    private IssuerSerial getIssuerSerial(String issuerDirName, BigInteger subjectSerial) {
        X500Name x500Name = new X500Name(issuerDirName);
        GeneralNames generalNames = new GeneralNames(new GeneralName(x500Name));
        ASN1Integer serial = new ASN1Integer(subjectSerial);
        return new IssuerSerial(generalNames, serial);
    }

    /**
     * Verifica se o certificado dado é o mesmo que está no atributo
     * @param certificate O certificado a ser comparado
     * @return Indica se o certificado dado é o mesmo que está no atributo
     */
    @Override
    public boolean match(Certificate certificate) {
        boolean match = false;
        X509Certificate x509Certificate = (X509Certificate) certificate;
        try {
            byte[] certificateHash = this.getCertificateHash(x509Certificate);
            byte[] signerCertificateHash = this.certs.get(0).getCertHash();
            match = this.compareBytes(certificateHash, signerCertificateHash) == 0;
        } catch (SignatureAttributeException e) {
            match = false;
        }
        return match;
    }

    /**
     * Verifica se dois arrays de bytes são iguais.
     * @param atual O array a ser comparado
     * @param expected O array esperado
     * @return Retorna 0 se são iguais ou 1 se são diferentes
     */
    protected int compareBytes(byte[] atual, byte[] expected) {
        int result = 0;
        int index = 0;
        while (index < atual.length && result == 0) {
            if (atual[index] > expected[index]) {
                result = 1;
            } else if (atual[index] < expected[index])
                result = -1;
            index++;
        }
        return result;
    }

    /**
     * Inibe o uso do construtor vazio default.
     */
    private IdAaSigningCertificate() {
    }

    /**
     * Faz uma cópia deste objeto
     * @return Uma cópia do objeto
     */
    @Override
    public CertSelector clone() {
        IdAaSigningCertificate clone = new IdAaSigningCertificate();
        for (ESSCertID cert : this.certs) {
            clone.certs.add(ESSCertID.getInstance((ASN1Sequence) cert.toASN1Primitive()));
        }
        clone.signatureVerifier = this.signatureVerifier;
        return clone;
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {

        return true;
    }
}
