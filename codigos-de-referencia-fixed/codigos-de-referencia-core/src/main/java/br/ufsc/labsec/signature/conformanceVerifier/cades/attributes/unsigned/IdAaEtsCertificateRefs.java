/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdContentType;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CertificateRefsException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Este atributo deve conter apenas todos certificados do caminho de
 * certificação do assinante, incluindo o certificado da Autoridade
 * Certificadora, e excluindo o certificado do signatário.
 * <p>
 * Somente uma instância deste atributo é permitida na assinatura.
 * <p>
 * 
 * Oid e esquema do atributo id-aa-ets-certificateRefs retirado do documento
 * ETSI TS 101 733 V1.8.1:
 * <p>
 * 
 * <pre>
 * id-aa-ets-certificateRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 21}
 * 
 * CompleteCertificateRefs ::= SEQUENCE OF OtherCertID
 * </pre>
 */
public class IdAaEtsCertificateRefs implements SignatureAttribute, CertSelector {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_ets_certificateRefs.getId();
    /**
     * Lista de certificados do atributo
     */
    private List<OtherCertID> certIds;
    /**
     * Um conjunto de hashs de certificados presentes no atributo para agilizar
     * a busca dentro de um certStore
     */
    private Set<byte[]> certificateIdentifierSet;
    /**
     * Algoritmo de cálculo de hash
     */
    private String algorithm;
    /**
     * Objeto de verificador
     */
    private AbstractVerifier signatureVerifier;

    /**
     * Construtor usado para validação do atributo.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeNotFoundException
     */
    public IdAaEtsCertificateRefs(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = signatureVerifier;
        CadesSignature signature = this.signatureVerifier.getSignature();
        Attribute genericEncoding = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(genericEncoding);
    }

    /**
     * Obtém os certificados armazenados no atributo.
     * @return A lista de certificados armazenados no atributo
     */
    public List<OtherCertID> getOtherCertIDs() {
        List<OtherCertID> otherCertIDs = new ArrayList<OtherCertID>(this.certIds);
        return otherCertIDs;
    }

    /**
     * Cria o atributo referênciando os certificados presentes na lista
     * <code>certificates</code>. Na referência será usado um algoritmo de hash,
     * a identificação desse algoritmo deve ser passada para
     * <code>digestAlgorithm</code>.
     * @param certificates Lista de certificados
     * @param digestAlgorithm O algoritmo de hash
     * @throws SignatureAttributeException
     */
    public IdAaEtsCertificateRefs(List<X509Certificate> certificates, String digestAlgorithm) throws SignatureAttributeException {
        if (certificates == null || digestAlgorithm == null) {
            throw new SignatureAttributeException("Os parâmetros não podem ser nulos");
        }
        if (certificates.size() == 0) {
            throw new SignatureAttributeException("A lista não contém nenhum certificado");
        }
        this.algorithm = digestAlgorithm;
        String algorithmName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(digestAlgorithm);
        if (algorithmName == null) {
            throw new SignatureAttributeException("O algoritmo de hash não é conhecido");
        }
        this.certIds = new ArrayList<OtherCertID>();
        this.certificateIdentifierSet = new HashSet<byte[]>();
        for (X509Certificate certificate : certificates) {
            byte[] certificateHash = this.getCertificateHash(certificate, algorithmName);
            IssuerSerial issuerSerial = this.getIssuerSerial(certificate.getIssuerDN().getName(), certificate.getSerialNumber());
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(digestAlgorithm);
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(oid);
            OtherCertID certId = new OtherCertID(algorithmIdentifier, certificateHash, issuerSerial);
            this.certIds.add(certId);
            this.certificateIdentifierSet.add(certificateHash);
        }
    }

    /**
     * Permite contruir o atributo a partir de sua codificação. O atributo será
     * decodificado e então o mesmo pode ser usado como {@link CertSelector}, o
     * que é útil na validação da assinatura.
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaEtsCertificateRefs(Attribute genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

    /**
     * Constrói um objeto {@link IdAaEtsCertificateRefs}
     * @param genericEncoding O atributo codificado
     */
    @SuppressWarnings("rawtypes")
    private void decode(Attribute genericEncoding) throws SignatureAttributeException {
    	
        ASN1Set attributeValues = genericEncoding.getAttrValues();
        this.certIds = new ArrayList<OtherCertID>();
        this.certificateIdentifierSet = new HashSet<byte[]>();

        Enumeration certificateRefs = attributeValues.getObjects();
		ASN1Sequence otherCertIdsSequence = (ASN1Sequence) certificateRefs.nextElement();
		Enumeration otherCertIds = otherCertIdsSequence.getObjects();
        while (otherCertIds.hasMoreElements()) {
        	        	
        	ASN1Object otherCertIdEncodable = (ASN1Object) otherCertIds.nextElement();
        	
            OtherCertID otherCertId = null;
            if (otherCertIdEncodable instanceof OtherCertID) {
                otherCertId = (OtherCertID) otherCertIdEncodable;
            } else {
                otherCertId = OtherCertID.getInstance(otherCertIdEncodable);
            }
            this.certIds.add(otherCertId);
            this.certificateIdentifierSet.add(otherCertId.getCertHash());
        }
        if (this.certIds.size() > 0) {
            this.algorithm = this.certIds.get(0).getAlgorithmHash().getAlgorithm().toString();
        } else {
            throw new SignatureAttributeException("O atributo codificado não é válido");
        }
    }

    /**
     * Calcula o hash do certificado
     * @param certificate O certificado
     * @return O Hash do certificado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    private byte[] getCertificateHash(X509Certificate certificate, String algorithm) throws SignatureAttributeException {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new CertificateRefsException(noSuchAlgorithmException.getMessage(), noSuchAlgorithmException.getStackTrace());
        }
        try {
            messageDigest.update(certificate.getEncoded());
        } catch (CertificateEncodingException certificateEncodingException) {
            throw new CertificateRefsException(certificateEncodingException.getMessage(), certificateEncodingException.getStackTrace());
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
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsCertificateRefs.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        int numberOfCertRefsAttributes = 0;
        for (String identifier : this.signatureVerifier.getSignature().getAttributeList()) {
            if (identifier.equals(this.getIdentifier())) {
                numberOfCertRefsAttributes++;
            }
        }
        if (numberOfCertRefsAttributes > 1) {
            CertificateRefsException certificateRefsException = new CertificateRefsException(CertificateRefsException.DUPLICATED_ATTRIBUTE);
            certificateRefsException.setCritical(this.isSigned());
            throw certificateRefsException;
        }
        CertPath certPath = this.signatureVerifier.getCertPath();
        if (certPath == null) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Não foi possível obter o caminho de certificação");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        @SuppressWarnings("unchecked")
        List<X509Certificate> certPathCertificates = (List<X509Certificate>) certPath.getCertificates();
        Set<X509Certificate> certPathSet = new HashSet<X509Certificate>(certPathCertificates);
        Set<OtherCertID> certIdSet = new HashSet<OtherCertID>(this.certIds);
        if (certPathSet.size() != certIdSet.size()) {
            CertificateRefsException certificateRefsException = new CertificateRefsException(
                    CertificateRefsException.WRONG_SIZE_OF_CERTIFICATES);
            certificateRefsException.setCritical(this.isSigned());
            throw certificateRefsException;
        }
        X509Certificate lastCertificate = certPathCertificates.get(certPathCertificates.size() - 1);
        CertificateTrustPoint certificateTrustPoint = this.signatureVerifier.getSignaturePolicy().getTrustPoint(
                lastCertificate.getIssuerX500Principal());
        X509Certificate trustPoint = (X509Certificate) certificateTrustPoint.getTrustPoint();
        List<X509Certificate> certPathToCompare = new ArrayList<X509Certificate>(certPathCertificates.subList(1, certPathCertificates.size()));
        certPathToCompare.add(trustPoint);
        Iterator<X509Certificate> certificateIterator = certPathToCompare.iterator();
        boolean equalBytes = false;
        String actualCertificate = "";
        for (OtherCertID otherCertID : this.certIds) {
            String algorithmID = otherCertID.getAlgorithmHash().getAlgorithm().getId();
            String algorithmName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmID);
            while ((!equalBytes) && certificateIterator.hasNext()) {
                X509Certificate x509Certificate = certificateIterator.next();
                byte[] x509CertificateHash = this.getCertificateHash(x509Certificate, algorithmName);
                equalBytes = this.compareBytes(otherCertID.getCertHash(), x509CertificateHash);
                actualCertificate = x509Certificate.getSubjectX500Principal().getName();
            }
            if (!equalBytes) {
                CertificateRefsException certificateRefsException = new CertificateRefsException(
                        CertificateRefsException.MISSING_CERTIFICATE, actualCertificate);
                certificateRefsException.setCritical(this.isSigned());
                throw certificateRefsException;
            }
            equalBytes = false;
            certificateIterator = certPathToCompare.iterator();
        }
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN.1
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        ASN1EncodableVector certificateRefsVector = new ASN1EncodableVector();
        for (OtherCertID certId : this.certIds) {
            certificateRefsVector.add(certId);
        }
        
        ASN1Sequence attrSeq = new DERSequence(certificateRefsVector);
        
        ASN1Set attributeValues = new DERSet(attrSeq);
        Attribute idAaEtsCertificateRefs = new Attribute(new ASN1ObjectIdentifier(this.getIdentifier()), attributeValues);
        
        return idAaEtsCertificateRefs;
    }

    /**
     * Informa se o atributo é assinado
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return false;
    }

    /**
     * Seleciona os certificados que tem sua identificação gravada no atributo
     * em questão
     */
    @Override
    public boolean match(Certificate certificate) {
        boolean result = certificate instanceof X509Certificate;
        if (result) {
            MessageDigest digester = null;
            try {
                digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(this.algorithm));
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                /* Não é possível afirmar que os certificados são iguais */
                noSuchAlgorithmException.printStackTrace();
                result = false;
            }
            byte[] hash = null;
            try {
                hash = digester.digest(certificate.getEncoded());
            } catch (CertificateEncodingException certificateEncodingException) {
                /* Não é possível afirmar que os certificados são iguais */
                certificateEncodingException.printStackTrace();
                result = false;
            }
            boolean found = false;
            Iterator<byte[]> certIds = this.certificateIdentifierSet.iterator();
            while (certIds.hasNext() && !found) {
                byte[] nextHash = certIds.next();
                found = this.compareBytes(nextHash, hash);
            }
            result = found;
        }
        return result;
    }

    /**
     * Verifica se os bytes são iguais
     * @param expected O byte experado
     * @param actual O byte atual
     * @return Indica se são iguais
     */
    private boolean compareBytes(byte[] expected, byte[] actual) {
        boolean result = expected.length == actual.length;
        int i = 0;
        while (result && i < expected.length) {
            result &= expected[i] == actual[i++];
        }
        return result;
    }

    /**
     * Retorna um objeto identico à instância para qual a mensagem foi enviada.
     * As alterações feitas no objeto retornado não afetam a instância antes
     * mencionada.
     */
    @Override
    public IdAaEtsCertificateRefs clone() {
        IdAaEtsCertificateRefs clone = new IdAaEtsCertificateRefs();
        clone.algorithm = this.algorithm;
        clone.certificateIdentifierSet = new HashSet<byte[]>(this.certificateIdentifierSet);
        clone.certIds = new ArrayList<OtherCertID>();
        clone.certIds.addAll(this.certIds);
        return clone;
    }

    /**
     * Construtor
     */
    private IdAaEtsCertificateRefs() {
    }

    /**
     * Retorna o tamanho da lista de certificados
     * @return O tamanho da lista de certificados
     */
    public int getCertIdSize() {
        return this.certIds.size();
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
