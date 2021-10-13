/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdContentType;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.exceptions.NotInICPException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;

import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.AttributeMap;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.TimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.TimeStampVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.TimeStampException;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Representa o carimbo do tempo da assinatura.
 * <p>
 * 
 * Oid e esquema do atributo id-aa-signatureTimeStampToken retirado do documento
 * ETSI TS 101 733 V1.8.1:
 * <p>
 * 
 * <pre>
 * id-aa-signatureTimeStampToken OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 14}
 * 
 * SignatureTimeStampToken ::= TimeStampToken
 * </pre>
 */
public class IdAaSignatureTimeStampToken extends TimeStamp implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId();
    /**
     * Objeto de verificador
     */
    protected AbstractVerifier signatureVerifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public IdAaSignatureTimeStampToken(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = signatureVerifier;
        CadesSignature signature = this.signatureVerifier.getSignature();
        Attribute genericEncoding = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(genericEncoding);
    }

    /**
     * Constrói um objeto {@link IdAaSignatureTimeStampToken}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaSignatureTimeStampToken(Attribute genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

    /**
     * Constrói um objeto {@link IdAaSignatureTimeStampToken} a partir de um
     * {@link ContentInfo}
     * @param contentInfo O conteúdo do carimbo do tempo
     * @throws SignatureAttributeException
     */
    public IdAaSignatureTimeStampToken(ContentInfo contentInfo) throws SignatureAttributeException {
        if (contentInfo == null) {
            throw new SignatureAttributeException("Os parametros de construção não podem ser nulos");
        }
        this.contentInfo = contentInfo;
    }

    /**
     * Constrói um objeto {@link IdAaSignatureTimeStampToken}
     * @param genericEncoding O atributo codificado
     */
    private void decode(Attribute genericEncoding) {
        Attribute timeStampAttribute;
        timeStampAttribute = genericEncoding;
        this.contentInfo = ContentInfo.getInstance((ASN1Sequence) timeStampAttribute.getAttrValues().getObjectAt(0));
    }

    /**
     * Indica o identificador do atributo.
     * @return Retorna "1.2.840.113549.1.9.16.2.14"
     */
    @Override
    public String getIdentifier() {
        return IdAaSignatureTimeStampToken.IDENTIFIER;
    }

    /**
     * Valida o atributo em seu próprio contexto de validação. Os casos de
     * retorno negativo dessa validação são indicados por exceções. Para efetuar
     * esta validação é necessário adicionar os certificados do caminho de
     * certificação da carimbadora no {@link CertStore} da classe
     * {@link br.ufsc.labsec.signature.Verifier}.
     * @param report O relatório de verificação do carimbo
     * @param stamps Lista de carimbos de tempo da assinatura
     * @throws SignatureAttributeException
     * @throws AIAException 
     */
    @Override
    public void validate(TimeStampReport report, List<TimeStamp> stamps) throws SignatureAttributeException {
        TimeStampToken timeStampToken = null;
        SignatureAttributeException exceptionToThrow = null;
        
        TimeStampVerifier verifier = null;
        
        try{
            verifier = makeTimeStampVerifier(this.getContentInfo().getEncoded(), stamps);
            verifier.setupValidationData(report);
        } catch (IOException e) {
            throw new TimeStampException(e);
        }
        
        report.setTimeStampIdentifier(AttributeMap.translateName(this.getIdentifier())); 
        report.setSchema(SignatureReport.SchemaState.VALID);
        try {
            timeStampToken = new TimeStampToken(this.contentInfo);
        } catch (TSPException tspException) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(tspException.getMessage());
            signatureAttributeException.setCritical(this.isSigned());
            exceptionToThrow = signatureAttributeException;
            report.setSchema(SignatureReport.SchemaState.INVALID);
        } catch (IOException ioException) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(ioException.getMessage());
            signatureAttributeException.setCritical(this.isSigned());
            exceptionToThrow = signatureAttributeException;
            report.setSchema(SignatureReport.SchemaState.INVALID);
        }

        List<CertificateCollection> certList = this.signatureVerifier.getCadesSignatureComponent().certificateCollection; 
        
        Certificate timeStampCertificate = null; 
        int i = 0;
        
        while (i < certList.size() && timeStampCertificate == null) {
        	X509CertSelector selector = new X509CertSelector();
			try {
				selector.setIssuer(new X500Principal(timeStampToken.getSID()
						.getIssuer().getEncoded()));
			} catch (IOException e) {
				throw new SignatureAttributeException(e);
			}
			selector.setSerialNumber(timeStampToken.getSID().getSerialNumber());

        	timeStampCertificate = (X509Certificate) certList.get(i).getCertificate(selector);
        	i++;
        } 
        
        if (timeStampCertificate != null) {

        	this.signatureVerifier.getCadesSignatureComponent().getSignatureIdentityInformation().addCertificates(
        			Collections.singletonList((X509Certificate) timeStampCertificate));
        	
            List<Certificate> certificateOfTimeStampTokenSidList = null;
            certificateOfTimeStampTokenSidList = Collections.singletonList(timeStampCertificate);
            X509Certificate timeStampAutorityCert = (X509Certificate) certificateOfTimeStampTokenSidList.get(0);
            report.setTimeStampName(timeStampAutorityCert.getSubjectX500Principal().toString());
            report.setTimeReference(this.getTimeReference());
            try {          	      	
                if (!timeStampToken.isSignatureValid(this.createSignerInformationVerifier(timeStampAutorityCert))) {
                    SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                            "Carimbo de tempo inválido. Carimbadora: " + timeStampAutorityCert.getSubjectX500Principal());
                    signatureAttributeException.setCritical(this.isSigned());
                    report.setAsymmetricCipher(false);
                    exceptionToThrow = signatureAttributeException;
                } else {
                    report.setAsymmetricCipher(true);
                }
            } catch (OperatorCreationException e) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "Carimbo de tempo inválido. Carimbadora: " + timeStampAutorityCert.getSubjectX500Principal());
                signatureAttributeException.setCritical(this.isSigned());
                report.setAsymmetricCipher(false);
                exceptionToThrow = signatureAttributeException;
            } catch (TSPException e) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "Carimbo de tempo inválido. Carimbadora: " + timeStampAutorityCert.getSubjectX500Principal());
                signatureAttributeException.setCritical(this.isSigned());
                report.setAsymmetricCipher(false);
                exceptionToThrow = signatureAttributeException;
            } catch (CMSException e) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "Carimbo de tempo inválido. Carimbadora: " + timeStampAutorityCert.getSubjectX500Principal());
                signatureAttributeException.setCritical(this.isSigned());
                report.setAsymmetricCipher(false);
                exceptionToThrow = signatureAttributeException;
            }
            try {
                timeStampToken.validate(this.createSignerInformationVerifier(timeStampAutorityCert));
            } catch (TSPValidationException tspValidationException) {
                String attrError = "O certificado deve conter o atributo ExtendedKeyUsage marcado como crítico.";
                TimeStampException timeStampException = new TimeStampException(attrError, tspValidationException);
                timeStampException.setCritical(this.isSigned());
                exceptionToThrow = timeStampException;
            } catch (TSPException tspException) {
                TimeStampException timeStampException = new TimeStampException(tspException.getMessage());
                timeStampException.setCritical(this.isSigned());
                exceptionToThrow = timeStampException;
            } catch (OperatorCreationException operatorCreationException) {
                String valError = "Falha ao validar o atributo carimbo de tempo";
                TimeStampException timeStampException = new TimeStampException(valError, operatorCreationException);
                timeStampException.setCritical(this.isSigned());
                exceptionToThrow = timeStampException;
            } catch (CMSException cmsException) {
                String valError = "Falha ao validar o atributo carimbo de tempo";
                TimeStampException timeStampException = new TimeStampException(valError, cmsException);
                timeStampException.setCritical(this.isSigned());
                exceptionToThrow = timeStampException;
            }
        } else {
            report.setAsymmetricCipher(false);
        }
        byte[] messageImprintBytes = timeStampToken.getTimeStampInfo().getMessageImprintDigest();
        String hashAlgorithmId = timeStampToken.getTimeStampInfo().getMessageImprintAlgOID().getId();
        byte[] signatureHash = null;
        try {
            signatureHash = this.getHashFromSignature(hashAlgorithmId);
        } catch (PbadException signatureException) {
            SignatureAttributeException signatureAttributeException = new TimeStampException(signatureException.getMessage());
            signatureAttributeException.setCritical(this.isSigned());
            exceptionToThrow = signatureAttributeException;
        }

        
        if (!MessageDigest.isEqual(signatureHash, messageImprintBytes)) {
        	
        	try {
                signatureHash = this.getHashFromSignature(hashAlgorithmId, false);
            } catch (PbadException signatureException) {
                SignatureAttributeException signatureAttributeException = new TimeStampException(signatureException.getMessage());
                signatureAttributeException.setCritical(this.isSigned());
                exceptionToThrow = signatureAttributeException;
            }
        	
        	if (!MessageDigest.isEqual(signatureHash, messageImprintBytes)) {
	            report.setHash(false);
	            TimeStampException timeStampException = new TimeStampException(TimeStampException.VALUE_HASH_ERROR);
	            timeStampException.setCritical(this.isSigned());
	            exceptionToThrow = timeStampException; 
        	} else {
        		report.setHash(true);
        	}
        	
        } else {
            report.setHash(true);
        }
        
        this.verifyAttributes(report,verifier);

        if (exceptionToThrow != null) {
            throw exceptionToThrow;
        }
    }

    /**
     * Realiza a verificação dos atributos do carimbo
     * @param report O relatório de verificação do carimbo
     * @param timeStampVerifier O verificador a ser utilizado na operação do carimbo
     * @throws SignatureAttributeException
     */
    private void verifyAttributes(TimeStampReport report, TimeStampVerifier timeStampVerifier) throws SignatureAttributeException {
        try {
            if (!timeStampVerifier.verify(report)) {
                TimeStampException timeStampException = new TimeStampException(timeStampVerifier.getValidationErrors(), this.getIdentifier());
                timeStampException.setCritical(this.isSigned());
                throw timeStampException;
            }
        } catch (TimeStampException timeStampException) {
            timeStampException.setCritical(this.isSigned());
            throw timeStampException;
        } catch (NotInICPException e) {
            throw e;
        }
    }

    /**
     * Obtém um {@link TimeStampVerifier}.
     * @param timeStamp Bytes do time stamp que se deseja verificar
     * @param stamps Lista de carimbos de tempo da assinatura
     * @return O objeto {@link TimeStampVerifier} criado
     * @throws TimeStampException
     */
    private TimeStampVerifier makeTimeStampVerifier(byte[] timeStamp, List<TimeStamp> stamps) throws TimeStampException {
        List<String> oidStamps = new ArrayList<>();
        for (TimeStamp ts: stamps) {
            oidStamps.add(ts.getIdentifier());
        }
        TimeStampVerifier verifier = this.signatureVerifier.getCadesSignatureComponent().getTimeStampVerifier();
        verifier.setTimeStamp(timeStamp, this.getIdentifier(), this.signatureVerifier.getSignaturePolicy(), this.signatureVerifier.getTimeReference(),
                oidStamps, this.isLast());
        return verifier;
    }

    /**
     * Verifica se o atributo é o último carimbo na assinatura
     * @return Indica se o carimbo é o último na assinatura
     */
    protected boolean isLast() {
        return false;
    }

    /**
     * Obtém um {@link SignerInformationVerifier}.
     * @param certificate Certificado final do caminho de certificação que se
     *            deseja validar
     * @return O objeto {@link SignerInformationVerifier} criado
     * @throws OperatorCreationException
     * @throws CMSException
     */
    protected SignerInformationVerifier createSignerInformationVerifier(X509Certificate certificate) throws OperatorCreationException,
        CMSException {
        JcaContentVerifierProviderBuilder contentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
        ContentVerifierProvider contentVerifierProvider = contentVerifierProviderBuilder.build(certificate);
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        
        CMSSignatureAlgorithmNameGenerator cmsSignatureAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
        SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        
        return new SignerInformationVerifier(cmsSignatureAlgorithmNameGenerator, signatureAlgorithmIdentifierFinder, contentVerifierProvider, digestCalculatorProvider);
    }

    /**
     * Codifica o atributo em seu formato básico, nesse caso {@link Attribute}
     * @return O atributo codificado
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        Attribute timeStampAttribute = new Attribute(new ASN1ObjectIdentifier(this.getIdentifier()), new DERSet(
                this.contentInfo.toASN1Primitive()));
        return timeStampAttribute;
    }

    /**
     * Retorna o conteúdo do carimbo em formato ASN.1
     * @return O conteúdo do carimbo em formato ASN.1
     */
    public DERSequence getArchiveTimeStampContentInfo() {
        return (DERSequence) this.contentInfo.toASN1Primitive();
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
     * Calcula o hash do atributo
     * @param hashAlgorithmId O algoritmo utilizado
     * @return O valor de hash do atributo
     * @throws PbadException Exceção em caso de erro durante o cálculo
     */
    @Override
    protected byte[] getHashFromSignature(String hashAlgorithmId) throws PbadException {
    	return getHashFromSignature(hashAlgorithmId, true);
    }

    /**
     * Calcula o hash do atributo
     * @param hashAlgorithmId O algoritmo utilizado
     * @param hashWithoutTag Indica a forma de cálculo da hash, de acordo com as notas 2 e 3 da pagina 109 do ETSI TS 101 733 V2.2.1.
     *                      Se verdadeiro indica que o calculo é feito sem incluir tag e length.
     * @return O valor de hash do atributo
     * @throws PbadException Exceção em caso de erro durante o cálculo
     */
    protected byte[] getHashFromSignature(String hashAlgorithmId, boolean hashWithoutTag) throws PbadException {
        return this.signatureVerifier.getSignature().getSignatureValueHash(
                AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(hashAlgorithmId));
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return false;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws PbadException {
        // TODO Auto-generated method stub

    }
}
