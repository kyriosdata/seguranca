/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CertValuesException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esse atributo é usado para guardar as informações de certificados da
 * assinatura. Ele deve conter no mínimo todos os certificados que o atributo
 * {@link IdAaEtsCertificateRefs} referencia, e mais o certificado do assinante.
 * <p>
 * Sendo assim, ele deve conter todos os certificados do caminho de
 * certificação, e o certificado da âncora de confiança. O
 * {@link IdAaEtsCertificateRefs} não guarda o certificado do assinante.
 * <p>
 * 
 * Oid e esquema do atributo id-aa-ets-certValues retirado do documento ETSI TS
 * 101 733 V1.8.1:
 * <p>
 * 
 * <pre>
 * id-aa-ets-certValues OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 23}
 *  
 * CertificateValues ::= SEQUENCE OF Certificate
 * </pre>
 */
public class IdAaEtsCertValues implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_ets_certValues.getId();
    /**
     * Lista de certificados
     */
    private List<X509Certificate> x509Certificates;
    /**
     * Objeto de verificador
     */
    private AbstractVerifier signatureVerifier;
    /**
     * Certificado do assinante
     */
    private X509Certificate signerCertificate;

    /**
     * <p>
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * </p>
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public IdAaEtsCertValues(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = signatureVerifier;
        CadesSignature signature = this.signatureVerifier.getSignature();
        Attribute genericEncoding = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(genericEncoding);
    }

    /**
     * Cria o atributo id-aa-ets-certvalues a partir de uma lista de
     * certificados.
     * @param certificates Lista de certificados que serão guardados no
     *            atributo
     * @throws SignatureAttributeException
     * @throws CertificateEncodingException
     */
    public IdAaEtsCertValues(X509Certificate signerCertificate, List<X509Certificate> certificates) throws SignatureAttributeException,
            CertificateEncodingException {
        if (signerCertificate == null) {
            throw new CertValuesException(CertValuesException.NULL_SIGNER_CERTIFICATE);
        }
        this.signerCertificate = signerCertificate;
        this.x509Certificates = new ArrayList<X509Certificate>();
        this.x509Certificates.add(this.signerCertificate);
        this.x509Certificates.addAll(certificates);
    }

    /**
     * Cria o atributo id-aa-ets-certvalues
     * @param genericEncoding O atributo codificado
     * @throws CertValuesException
     */
    public IdAaEtsCertValues(Attribute genericEncoding) throws CertValuesException {
        this.decode(genericEncoding);
    }

    /**
     * Cria o atributo id-aa-ets-certvalues
     * @param genericEncoding O atributo codificado
     * @throws CertValuesException
     */
    private void decode(Attribute genericEncoding) throws CertValuesException {

        ASN1Set attributeValues = genericEncoding.getAttrValues();
        ASN1Sequence certificatesSequence = (ASN1Sequence) attributeValues.getObjectAt(0);
        this.x509Certificates = new ArrayList<X509Certificate>();
        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException certificateException) {
            throw new CertValuesException(certificateException.getMessage(), certificateException.getStackTrace());
        }
        ByteArrayInputStream certificateStream = null;
        X509Certificate x509Certificate = null;
        for (int i = 0; i < certificatesSequence.size(); i++) {
            try {
                certificateStream = new ByteArrayInputStream(certificatesSequence.getObjectAt(i).toASN1Primitive().getEncoded());
            } catch (IOException ioException) {
                throw new CertValuesException(ioException.getMessage(), ioException.getStackTrace());
            }
            try {
                x509Certificate = (X509Certificate) certificateFactory.generateCertificate(certificateStream);
            } catch (CertificateException certificateException) {
                throw new CertValuesException(certificateException.getMessage(), certificateException.getStackTrace());
            }
            this.x509Certificates.add(x509Certificate);
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsCertValues.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException, EncodingException {
        int numberOfCertValueAttributes = 0;
        for (String identifier : this.signatureVerifier.getSignature().getAttributeList()) {
            if (identifier.equals(this.getIdentifier())) {
                numberOfCertValueAttributes++;
            }
        }
        if (numberOfCertValueAttributes > 1) {
            CertValuesException certValuesException = new CertValuesException(CertValuesException.DUPLICATED_ATTRIBUTE);
            certValuesException.setCritical(this.isSigned());
            throw certValuesException;
        }
        if (!this.signatureVerifier.getSignature().getAttributeList().contains(IdAaEtsCertificateRefs.IDENTIFIER)) {
            CertValuesException certValuesException = new CertValuesException(CertValuesException.CERTIFICATE_REFS_NOT_FOUND);
            certValuesException.setCritical(this.isSigned());
            throw certValuesException;
        }
        Attribute idAaEtsCertificateRefsEncoding = this.signatureVerifier.getSignature().getEncodedAttribute(
                IdAaEtsCertificateRefs.IDENTIFIER, 0);
        IdAaEtsCertificateRefs idAaEtsCertificateRefs = new IdAaEtsCertificateRefs(idAaEtsCertificateRefsEncoding);
        List<OtherCertID> otherCertIDs = idAaEtsCertificateRefs.getOtherCertIDs();
        boolean equalBytes = false;
        Iterator<X509Certificate> x509CertificatesIterator = this.x509Certificates.iterator();
        for (OtherCertID otherCertID : otherCertIDs) {
            String algorithmID = otherCertID.getAlgorithmHash().getAlgorithm().getId();
            String algorithmName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmID);
            while ((!equalBytes) && x509CertificatesIterator.hasNext()) {
                X509Certificate x509Certificate = x509CertificatesIterator.next();
                byte[] x509CertificateHash = this.getCertificateHash(x509Certificate, algorithmName);
                equalBytes = this.compareBytes(otherCertID.getCertHash(), x509CertificateHash);
            }
            if (!equalBytes) {
                CertValuesException certValuesException = new CertValuesException(CertValuesException.INVALID_CERTIFICATE, otherCertID
                        .getIssuerSerial().getIssuer().toString());
                certValuesException.setCritical(this.isSigned());
                throw certValuesException;
            }
            equalBytes = false;
            x509CertificatesIterator = this.x509Certificates.iterator();
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
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    noSuchAlgorithmException.getMessage(), noSuchAlgorithmException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        try {
            messageDigest.update(certificate.getEncoded());
        } catch (CertificateEncodingException certificateEncodingException) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    certificateEncodingException.getMessage(), certificateEncodingException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        return messageDigest.digest();
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN.1
     */
    @SuppressWarnings("resource")
	public Attribute getEncoded() throws SignatureAttributeException {
        ASN1EncodableVector certValuesVector = new ASN1EncodableVector();
        ASN1InputStream decoder = null;
        for (X509Certificate x509Certificate : this.x509Certificates) {
            try {
                decoder = new ASN1InputStream(x509Certificate.getEncoded());
            } catch (CertificateEncodingException certificateEncodingException) {
                throw new SignatureAttributeException(certificateEncodingException.getMessage(),
                        certificateEncodingException.getStackTrace());
            }
            try {
                certValuesVector.add(decoder.readObject());
            } catch (IOException ioException) {
                throw new SignatureAttributeException(ioException.getMessage(), ioException.getStackTrace());
            }
        }
        DERSequence attributeSequence = new DERSequence(certValuesVector);
        ASN1Set attributeSet = new DERSet(attributeSequence);
        Attribute asn1EncodedAttribute = new Attribute(new ASN1ObjectIdentifier(this.getIdentifier()), attributeSet);
        return asn1EncodedAttribute;
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
     * Usado para obter a lista de certificados que foram armazenados no
     * atributo id-aa-ets-certvalues.
     * @return Lista de certificados armazenados no atributo
     *         id-aa-ets-certvalues.
     */
    public List<X509Certificate> getCertValues() {
        List<X509Certificate> certValues = new ArrayList<X509Certificate>(this.x509Certificates);
        return certValues;
    }

    /**
     * Obtém o certificado do assinante
     * @return O certificado do assinante.
     */
    public X509Certificate getSignerCertificate() {
        return this.signerCertificate;
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
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return true;
    }
}
