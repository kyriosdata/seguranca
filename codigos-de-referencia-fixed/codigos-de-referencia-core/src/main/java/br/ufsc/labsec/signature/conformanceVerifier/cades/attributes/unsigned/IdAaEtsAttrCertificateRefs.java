/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SigningCertificateException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo IdAaEtsAttrCertificateRefs guarda referências dos certificados do
 * caminho de certificação do certificado de atributos.
 * <p>
 * 
 * Oid e esquema do atributo attribute-certificate-references retirado do
 * documento ETSI TS 101 733 V1.8.1:
 * <p>
 * 
 * <pre>
 * id-aa-ets-attrCertificateRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 44}
 * 
 * AttributeCertificateRefs ::= SEQUENCE OF OtherCertID
 * </pre>
 */
public class IdAaEtsAttrCertificateRefs implements SignatureAttribute {

    public static final String IDENTIFIER = "1.2.840.113549.1.9.16.2.44";
    /**
     * Conjunto de identificadores dos certificados no atributo
     */
    private Set<byte[]> certificateIdentifierSet;
    /**
     * Lista de certificados
     */
    private List<OtherCertID> certIds;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public IdAaEtsAttrCertificateRefs(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        CadesSignature signature = signatureVerifier.getSignature();
        Attribute genericEncoding = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(genericEncoding);
    }

    /**
     * Cria o atributo que referencia os certificados do caminho que são
     * passados na lista <code>certificates</code>.
     * <p>
     * Também guarda o algoritmo de hash passado em <code>digestAlgorithm</code>.
     * @param certificates A lista de certificados
     * @param digestAlgorithm O algoritmo de hash
     * @throws SignatureAttributeException
     */
    public IdAaEtsAttrCertificateRefs(List<X509Certificate> certificates, String digestAlgorithm) throws SignatureAttributeException {
        if (certificates == null || digestAlgorithm == null) {
            throw new SignatureAttributeException("Os parâmetros não podem ser nulos");
        }
        if (certificates.size() == 0) {
            throw new SignatureAttributeException("O caminho de certificação está vazio.");
        }
        String algorithmName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(digestAlgorithm);
        if (algorithmName == null) {
            throw new SignatureAttributeException("O algoritmo de hash não é conhecido");
        }
        this.certIds = new ArrayList<OtherCertID>();
        this.certificateIdentifierSet = new HashSet<byte[]>();
        for (X509Certificate certificate : certificates) {
            byte[] certificateHash = this.getCertificateHash(certificate, algorithmName);
            IssuerSerial issuerSerial = this.getIssuerSerial(certificate.getIssuerDN().getName(), certificate.getSerialNumber());
            AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(digestAlgorithm);
            OtherCertID certId = new OtherCertID(algorithmIdentifier, certificateHash, issuerSerial);
            this.certIds.add(certId);
            this.certificateIdentifierSet.add(certificateHash);
        }
    }

    /**
     * Constrói um objeto {@link IdAaEtsAttrCertificateRefs}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaEtsAttrCertificateRefs(Attribute attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link IdAaEtsAttrCertificateRefs}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Attribute genericEncoding) throws SignatureAttributeException {
        Attribute attribute;
        attribute = genericEncoding;
        ASN1Set attributeValues = attribute.getAttrValues();
        this.certIds = new ArrayList<OtherCertID>();
        this.certificateIdentifierSet = new HashSet<byte[]>();
        Enumeration<?> certificateRefs = attributeValues.getObjects();
        while (certificateRefs.hasMoreElements()) {
            ASN1Encodable otherCertIdEncodable = (ASN1Encodable) certificateRefs.nextElement();
            OtherCertID otherCertId = null;
            if (otherCertIdEncodable instanceof OtherCertID) {
                otherCertId = (OtherCertID) otherCertId;
            } else {
                otherCertId = OtherCertID.getInstance((ASN1Sequence) otherCertIdEncodable);
            }
            this.certIds.add(otherCertId);
            this.certificateIdentifierSet.add(otherCertId.getCertHash());
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
            throw new SignatureAttributeException(SigningCertificateException.NO_SUCH_ALGORITHM_EXCEPTION,
                    noSuchAlgorithmException.getStackTrace());
        }
        try {
            messageDigest.update(certificate.getEncoded());
        } catch (CertificateEncodingException certificateEncodingException) {
            throw new SignatureAttributeException(SigningCertificateException.CERTIFICATE_ENCODING_EXCEPTION,
                    certificateEncodingException.getStackTrace());
        }
        return messageDigest.digest();
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsAttrCertificateRefs.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN.1
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        ASN1EncodableVector attrCertificateRefsVector = new ASN1EncodableVector();
        for (OtherCertID certId : this.certIds) {
            attrCertificateRefsVector.add(certId);
        }
        ASN1Set attributeValues = new DERSet(attrCertificateRefsVector);
        Attribute idAaEtsAttrCertificateRefs = new Attribute(new ASN1ObjectIdentifier(this.getIdentifier()), attributeValues);
        return idAaEtsAttrCertificateRefs;
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
     * Cria um objeto {@link IssuerSerial} com as informações dadas
     * @param issuerDirName Nome do emissor do certificado
     * @param subjectSerial Número de série do certificado emitido
     * @return O {@link IssuerSerial} criado
     */
    private IssuerSerial getIssuerSerial(String issuerDirName, BigInteger subjectSerial) throws SignatureAttributeException {
        X500Principal issuer = null;
        try {
            issuer = new X500Principal(new X500Name(issuerDirName).getEncoded());
        } catch (IOException iOException) {
            throw new SignatureAttributeException(SignatureAttributeException.PROBLEMS_TO_DECODE + this.getIdentifier());
        }
        GeneralNames generalNames = new GeneralNames(GeneralName.getInstance(issuer));
        ASN1Integer serial = new ASN1Integer(subjectSerial);
        return new IssuerSerial(generalNames, serial);
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
