/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes;

import java.io.IOException;
import java.security.cert.*;
import java.sql.Time;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.*;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.*;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertificationPathException;
import br.ufsc.labsec.signature.exceptions.*;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AttributeParams;
import br.ufsc.labsec.signature.CertificateValidation.ValidationResult;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.tsa.TimeStampVerifierInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdContentType;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdMessageDigest;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CertValuesException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureVerifierException;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;


/**
 * Responsável pela verificação de carimbos do tempo
 * 
 */
public class TimeStampVerifier extends AbstractVerifier implements TimeStampVerifierInterface {

    private static final String EXTENDED_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.8";
	private static final String TIMESTAMPINVALID = "The TimeStamp isn't a valid ContentInfo";
    private static final String SIGNINGCERTIFICATEV1Warning = "Embora o DOC-ICP-15 requeira o uso do atributo SigningCertificateV1"
            + " e como consequência o uso do algoritmo de hash SHA-1, o uso deste algoritmo não é mais recomendado. Portanto, "
            + "substituir em assinaturas futuras o atributo SigningCertificateV1 pelo SigningCertificateV2.";
    /**
     * Lista de atributos obrigatórios no carimbo
     */
    private List<String> mandatedAttributes;
    /**
     * Política de assinatura da assinatura que contém o carimbo
     */
    private SignaturePolicyInterface policy;
    /**
     * Lista de erros durante a verificação
     */
    private List<String> errors;
    /**
     * Horário do carimbo de tempo
     */
    private Time timeStampGenerationTime;


    /**
     * Construtor do verificador de carimbos do tempo
     * @param cadesSignatureComponent Componente de assinatura CAdES
     */
    public TimeStampVerifier(CadesSignatureComponent cadesSignatureComponent) {
        this.component = cadesSignatureComponent;
        this.policy = cadesSignatureComponent.signaturePolicyInterface;
        this.errors = new ArrayList<String>();
    }

    /**
     * Inicializa um {@link TimeStampVerifier}
     * @param timeStamp Carimbo a ser verificado
     * @param timeStampIdentifier Identificador do carimbo do tempo
     * @param timeReference Referência do tempo //FIXME
     * @param isLast Indica se é o último carimbo a ser verificado
     * @return Indica se a inicilização foi realizada com sucesso
     */
    public boolean setTimeStamp(byte[] timeStamp, String timeStampIdentifier, SignaturePolicyInterface policyInterface, Time timeReference,
                                List<String> stamps, boolean isLast) {

        this.policy = policyInterface;

        this.errors = new ArrayList<String>();
        ContentInfo contentInfo = null;

        try {
            ASN1InputStream inputStream = new ASN1InputStream(timeStamp);
            contentInfo = ContentInfo.getInstance(inputStream.readObject());
        } catch (IOException e1) {
            this.anotateError(TIMESTAMPINVALID);
            return false;
        }

        try {
            TimeStampToken tst = new TimeStampToken(contentInfo);
            this.timeStampGenerationTime = new Time(tst.getTimeStampInfo().getGenTime().getTime());
        } catch (TSPException | IOException e1) {
            e1.printStackTrace();
        }
        
        CadesSignature timeStampAsSignature = null;
        try {
        	CMSSignedData cmsSignedData = new CMSSignedData(contentInfo);
            CadesSignatureContainer container = new CadesSignatureContainer(cmsSignedData);
            timeStampAsSignature = container.getSignatureAt(0);
        } catch (EncodingException | CMSException e) {
            this.anotateError(TIMESTAMPINVALID);
            return false;
        }

        try {
            this.initialize(timeStampAsSignature, null, true);
        } catch (SignatureVerifierException e) {
            this.anotateError("Couldn't initialize the TimeStampVerifierCorrectly");
            return false;
        }

        createMandatedAttributes(stamps, timeStampIdentifier,isLast);

        this.policy = this.getSignaturePolicy();
        // this.certStore = this.getCertStore();
        if (this.getOcspList() != null) {
            this.ocspRespList = new ArrayList<OCSPResp>(this.getOcspList());
            this.ocspServerCertificate = this.getOcspServerCertificate();
        }

        this.setTimeReference(timeReference);

        return true;
    }

    /**
     * Retira os atributos de referência/valor de revogação e certificados da lista dada
     * @param attributes A lista de atributos a ser modificada
     * @param onlyValues Indica se apenas os atributos de valor devem ser removidos
     */
    private void removeRevCertRefsValues(List<String> attributes,
                                         boolean onlyValues) {
        // CAdES
        if (!onlyValues) {
            attributes.remove(IdAaEtsRevocationRefs.IDENTIFIER);
            attributes.remove(IdAaEtsCertificateRefs.IDENTIFIER);
        }
        attributes.remove(IdAaEtsRevocationValues.IDENTIFIER);
        attributes.remove(IdAaEtsCertValues.IDENTIFIER);

        // XAdES
        if (!onlyValues) {
            attributes.remove(CompleteRevocationRefs.IDENTIFIER);
            attributes.remove(CompleteCertificateRefs.IDENTIFIER);
        }
        attributes.remove(RevocationValues.IDENTIFIER);
        attributes.remove(CertificateValues.IDENTIFIER);
    }

    /**
     * Popula a lista de atributos obrigatórios de acordo com a política do carimbo
     * @param stamps A lista de carimbos de tempo da assinatura
     * @param timeStampIdentifier O identificador do carimbo de tempo
     * @param isLast Indica se o carimbo é o último a ser verificado
     */
    private void createMandatedAttributes(List<String> stamps, String timeStampIdentifier, boolean isLast) {
        this.mandatedAttributes = new ArrayList<>();

        // Tabelas A.6, A.8, A.10, A.12 do DOC-ICP-15.03 (v. 7.4)
        this.mandatedAttributes.add(IdContentType.IDENTIFIER);
        this.mandatedAttributes.add(IdMessageDigest.IDENTIFIER);

        String oid = this.policy.getReport().getOid();
        String oldCadesXadesPolicy = "(.*)2.16.76.1.7.1.([0-9]|10).([1-2]|1.1)[) ]$";

        if (oid.matches(oldCadesXadesPolicy)) {
            this.mandatedAttributes.add(IdAaSigningCertificate.IDENTIFIER);
        } else {
            this.mandatedAttributes.add(IdAaSigningCertificateV2.IDENTIFIER);
        }

        List<String> unsignedAttributes = this.policy.getMandatedUnsignedVerifierAttributeList();

        boolean isAnyStampButArchive = timeStampIdentifier.equals(
                PKCSObjectIdentifiers.id_aa_ets_contentTimestamp.getId())
                || timeStampIdentifier.equals(IdAaSignatureTimeStampToken.IDENTIFIER)
                || timeStampIdentifier.equals(IdAaEtsEscTimeStamp.IDENTIFIER)
                || timeStampIdentifier.equals(SignatureTimeStamp.IDENTIFIER)
                || timeStampIdentifier.equals(SigAndRefsTimeStamp.IDENTIFIER);

        // Tabelas A.7, A.9, A.11 do DOC-ICP-15.03 (v. 7.4)
        if (isAnyStampButArchive) {
            if (oid.contains("RB") || oid.contains("RT")) {
                removeRevCertRefsValues(unsignedAttributes, false);
            } else if (oid.contains("RV")) {
                removeRevCertRefsValues(unsignedAttributes, true);
            }
        }

        boolean hasContentButNotRefs =
                (timeStampIdentifier.equals(IdAaSignatureTimeStampToken.IDENTIFIER) &&
                        !stamps.contains(IdAaEtsEscTimeStamp.IDENTIFIER)) ||
                        (timeStampIdentifier.equals(SignatureTimeStamp.IDENTIFIER) &&
                                !stamps.contains(SigAndRefsTimeStamp.IDENTIFIER));

        boolean hasRefsButNotArchive =
                (timeStampIdentifier.equals(IdAaEtsEscTimeStamp.IDENTIFIER) &&
                        !stamps.contains(IdAaEtsArchiveTimeStampV2.IDENTIFIER)) ||
                        (timeStampIdentifier.equals(SigAndRefsTimeStamp.IDENTIFIER) &&
                                !stamps.contains(ArchiveTimeStamp.IDENTIFIER));

        boolean isArchiveStamp = timeStampIdentifier.equals(IdAaEtsArchiveTimeStampV2.IDENTIFIER) ||
                timeStampIdentifier.equals(ArchiveTimeStamp.IDENTIFIER);

        // Tabelas A.9, A.11, A.13 do DOC-ICP-15.03 (v. 7.4)
        if (hasContentButNotRefs || hasRefsButNotArchive || (isArchiveStamp && isLast)) {
            removeRevCertRefsValues(unsignedAttributes, false);
        }

        // CAdES
        unsignedAttributes.remove(IdAaEtsArchiveTimeStampV2.IDENTIFIER);
        unsignedAttributes.remove(IdAaSignatureTimeStampToken.IDENTIFIER);
        unsignedAttributes.remove(IdAaEtsEscTimeStamp.IDENTIFIER);

        // XAdES
        unsignedAttributes.remove(ArchiveTimeStamp.IDENTIFIER);
        unsignedAttributes.remove(SignatureTimeStamp.IDENTIFIER);
        unsignedAttributes.remove(SigAndRefsTimeStamp.IDENTIFIER);

        if (this.policy.isXml()) {
            List<String> actualUnsignedAttributes = new ArrayList<>();
            for (String s : unsignedAttributes) {
                actualUnsignedAttributes.add(AttributeMapCadesXades.getAttributeClass(s));
            }
            unsignedAttributes = actualUnsignedAttributes;
        }

        this.mandatedAttributes.addAll(unsignedAttributes);
    }

    /**
     * Adicina um erro à lista de erros
     * @param error O erro a ser adicionado
     */
    private void anotateError(String error) {
        this.errors.add(error);
    }

    /**
     * Valida os atributos do carimbo do tempo
     * @param report O relatório de verificação do carimbo
     * @return Indica se o carimbo é válido
     */
    @Override
    public boolean verify(SignatureReport report) throws NotInICPException {

        this.policy = this.component.signaturePolicyInterface;
        
        this.signerCert = null;

        TimeStampReport timeStampReport = (TimeStampReport) report;
        
        report.setPresent(true);
        
        this.exceptions = new ArrayList<PbadException>();

        try {
           
            this.setSignerCert();
        } catch (Throwable e) {
            Application.logger.log(Level.WARNING, "Não foi possível obter o certificado do assinante", e);
        }

        if (this.signerCert != null) {
            timeStampReport.setTimeStampName(this.signerCert.getSubjectX500Principal().toString());
        } else {
            timeStampReport.setTimeStampName("Carimbadora desconhecida");
        }
        timeStampReport.setTimeReference(this.timeStampGenerationTime);
        
        this.certPath = this.component.certificateValidation.generateCertPath(this.signerCert, this.policy.getTimeStampTrustAnchors(), getTimeReference());
        if (this.certPath == null) {
            throw new NotInICPException(NotInICPException.TIMESTAMP_SIGNATURE);
        }
        this.checkAcceptablePolicies();


        /*
         * Como este método configura o atributo `hash` da classe SignatureReport,
         * é necessário verificar a integridade da assinatura antes dos atributos.
         */
        this.verifySignIntegrity(report);

        List<PbadException> warnings = new ArrayList<PbadException>();
        List<PbadException> errors = new ArrayList<PbadException>();
        List<String> timestampAttributeList = this.signature.getAttributeList();
        report.setRequiredRules(this.mandatedAttributes.toString());
        report.setProhibitedRules("not implemented.");

        for (String mandatedAttribute : this.mandatedAttributes) {
            if (!timestampAttributeList.contains(mandatedAttribute)) {
                errors.add(new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.MISSING_MANDATED_ATTRIBUTE,
                        mandatedAttribute));

                AttribReport attribReport = new AttribReport();
                attribReport.setAttribName(AttributeMap.translateName(mandatedAttribute));
                attribReport.setError(true);
                attribReport.setErrorMessage(new SignatureAttributeNotFoundException(
                        SignatureAttributeNotFoundException.MISSING_MANDATED_ATTRIBUTE, mandatedAttribute).getMessage());
                
                report.addAttribRequiredReport(attribReport);
            }
        }
        List<String> attributesToExclude = new ArrayList<String>();
        this.verifyAttributesInMandatedList(warnings, errors, timestampAttributeList, this.mandatedAttributes, attributesToExclude, report);
        
        addWarningsInReport(report);
                
        verifyOnlyUnmandatedAttributes(timestampAttributeList, this.mandatedAttributes, attributesToExclude, report);
        
        errors.addAll(this.validateCertPath(report));
    
        this.exceptions.addAll(errors);
        boolean isValid = (errors.size() == 0);
        this.exceptions.addAll(warnings);
        return isValid;
    }

	/**
     * Adiciona um alerta no atributo IdAaSigningCertificate caso ele esteja presenta no carimbo
	 * @param report O relatório de verificação do carimbo
	 */
	private void addWarningsInReport(SignatureReport report) {
		
		for(AttribReport attrReport : report.getRequiredAttrib()) {
			
        	if(attrReport.getAttribName().equals(AttributeMap.translateName(IdAaSigningCertificate.IDENTIFIER))){
        		String prefix = (attrReport.hasWarning()) ? attrReport.getWarningMessage() + "\n" : "";
        		attrReport.setWarningMessage(prefix + SIGNINGCERTIFICATEV1Warning);
        	}
        }
	}

    /**
     * Valida o caminho de certificação
     * @param report O relatório de verificação do carimbo
     * @return Lista com as exceções que ocorreram durante a validação do caminho
     */
	//FIXME Ta muito errado essa exceção
    private List<PbadException> validateCertPath(SignatureReport report) {
        ArrayList<PbadException> exceptions = new ArrayList<PbadException>();
        
        Set<TrustAnchor> trustAnchors = this.policy.getTimeStampTrustAnchors();
                
        if(trustAnchors.size() == 0) {
            trustAnchors = this.policy.getSigningTrustAnchors();
        }
        
       ValidationResult validationResult = getCadesSignatureComponent().certificateValidation.validate(this.signerCert,
                trustAnchors, this.policy.getTimeStampRevocationReqs(), this.getTimeReference(), report);

        String validationMessage = validationResult.getMessage();
        if (validationResult != ValidationResult.valid) {
            exceptions.add(new PbadException(validationMessage));
        }
		if(this.signerCert != null) {
			try {
				List<String> extendedKeyYsage = this.signerCert.getExtendedKeyUsage();
				if (!extendedKeyYsage.contains(EXTENDED_KEY_USAGE_OID)) {
					validationResult = ValidationResult.invalid;
					validationResult.setMessage(
                            validationMessage + "\nCertificado do carimbo do tempo não possui a extensão de Carimbo do Tempo.");
				}
			} catch (CertificateParsingException e) {
				validationResult.setMessage(validationMessage
						+ "\nNão foi possível verificar se o certificado do carimbo de tempo possui permissão para esta emissão.");
			} 
		} else {
			validationResult.setMessage(validationMessage
					+ "\nNão foi possível verificar se o certificado do carimbo de tempo possui permissão para esta emissão.");
		}

        report.verifyValidationResult(validationResult);
        return exceptions;
    }

    /**
     * Percorre o caminho de certificação verificando se as políticas usadas
     * para cada certificado se encontram dentro das permitidas pela política de
     * assinatura.
     * @return Indica se não há nenhum certificado com uma política
     *         de certificação não permitida
     * @throws CertificationPathException Exceção em caso de erro no caminho de certificação
     */
    private void checkAcceptablePolicies() {
        // @SuppressWarnings("unchecked")
        // List<X509Certificate> certPathCertificates = (List<X509Certificate>)
        // this.certPath.getCertificates();
        // X509Certificate lastCa =
        // certPathCertificates.get(certPathCertificates.size() - 1);
        // CertificateTrustPoint trustPoint =
        // this.policy.getTimeStampTrustPoint(lastCa.getIssuerX500Principal());
        // try {
        // super.checkAcceptablePolicies(trustPoint);
        // } catch (CertificationPathException certificationPathException) {
        // this.exceptions.add(certificationPathException);
        // }
    }

    /**
     * Retorna a lista dos erros que ocorreram na última validação
     * @return A lista de erros
     */
    public List<Exception> getValidationErrors() {
        List<Exception> resulting = null;
        if (this.exceptions != null) {
            resulting = new ArrayList<Exception>(this.exceptions);
        }
        return resulting;
    }

    /**
     * Retorna a política de assinatura da assinatura que contém o carimbo do
     * tempo
     * @return A política de assinatura
     */
    public SignaturePolicyInterface getSignaturePolicy() {
        return this.policy;
    }

    /**
     * Cria e adiciona um atributo na lista de atributos não assinados
     * @param attributeId O identificador do atributo
     * @param params Os parâmetros do atributo
     */
    @Override
    public void addAttribute(String attributeId, AttributeParams params) {
        try {
            this.signature.addUnsignedAttribute(this.buildAttribute(attributeId, params));
        } catch (SignatureAttributeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (PbadException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * Constrói um atributo da assinatura
     * @param attributeId O identificador do atributo
     * @param params Os parâmetros do atributo
     * @return O atributo gerado
     */
    private SignatureAttribute buildAttribute(String attributeId, AttributeParams params) {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * Remove um atributo da lista de atributos não-assinados
     * @param attributeId O identificador do atributo
     * @param index A posição na assinatura do atributo a ser retirado
     */
    @Override
    public void removeAttribute(String attributeId, int index) {
        try {
            this.signature.removeUnsignedAttribute(attributeId, index);
        } catch (SignatureAttributeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * Inicializa os dados de validação dos atributos antes de validar a assinatura
     * @param report A estrutura de relatório para inserção dos dados de validação
     * @throws AIAException
     */
    public void setupValidationData(TimeStampReport report) {
        List<X509Certificate> idAaEtsCertValues = null;
        List<X509CRL> crlsList;
        
        try {
        	List<X509Certificate> certs = this.signature.getCertificates();
        	SigningCertificateInterface signingCertificate = null;
        	if (this.signature.getAttributeList().contains(IdAaSigningCertificate.IDENTIFIER)) {
        		signingCertificate = new IdAaSigningCertificate(this.signature.getEncodedAttribute(IdAaSigningCertificate.IDENTIFIER));
        	} else {
        		signingCertificate = new IdAaSigningCertificateV2(this.signature.getEncodedAttribute(IdAaSigningCertificateV2.IDENTIFIER));
        	}

            X509Certificate signerCert = null;
        	for (X509Certificate cert: certs) {
        		if (signingCertificate.match(cert)) {
                    signerCert = cert;
                    break;
        		}
        		
        	}

            Set<TrustAnchor> trustAnchors = this.policy.getTimeStampTrustAnchors();
            if (trustAnchors.size() == 0) {
                trustAnchors = this.policy.getSigningTrustAnchors();
            }
            Time timeReference = new Time(SystemTime.getSystemTime());
            CertPath certPath = this.getCadesSignatureComponent().certificateValidation.generateCertPath(signerCert,
                    trustAnchors, timeReference);

            if (certPath != null) {
                List<? extends Certificate> certificates = certPath.getCertificates();

                for (int i = 0; i < certificates.size() - 1; i++) {
                    X509Certificate subjectCert = (X509Certificate) certificates.get(i);
                    X509Certificate issuerCert = (X509Certificate) certificates.get(i + 1);
                    report.addValidation(ValidationDataService.getValidationData(subjectCert,issuerCert));
                }

                X509Certificate lastCertificate = (X509Certificate) certificates.get(certificates.size() - 1);
                CertificateTrustPoint trustPoint = this.component.signaturePolicyInterface
                        .getTrustPoint(lastCertificate
                                .getIssuerX500Principal());
                if (trustPoint != null) {
                    report.addValidation(ValidationDataService.getValidationData(
                            lastCertificate,
                            (X509Certificate) trustPoint.getTrustPoint()));
                }
            }
        } catch (IOException | SignatureAttributeException | CertificateException e) {
			Application.logger.log(Level.FINE, e.getMessage());
		}
        
        
        if (this.signature.getAttributeList().contains(IdAaEtsCertValues.IDENTIFIER)) {
             idAaEtsCertValues = this.getCertificateValues(this.signature);
             this.component.getSignatureIdentityInformation().addCertificates(idAaEtsCertValues);
            if (this.signature.getAttributeList().contains(IdAaEtsRevocationValues.IDENTIFIER)) {
                crlsList = this.getSignatureRevocationValues(this.signature);
                this.component.getSignatureIdentityInformation().addCrl(idAaEtsCertValues, crlsList);
            }
        }
    }

    /**
     * Retorna o horário do carimbo
     * @return O horário do carimbo
     */
    @Override
    public Time getTimeStampGenerationTime() {
        return this.timeStampGenerationTime;
    }

    /**
     * Retorna a lista de certificados do atributo {@link IdAaEtsCertValues}
     * @param signature A assinatura que contém o atributo
     * @return A lista de certificados
     */
    private List<X509Certificate> getCertificateValues(CadesSignature signature) {
        IdAaEtsCertValues certValues = null;
        try {
            Attribute element = signature.getEncodedAttribute(IdAaEtsCertValues.IDENTIFIER);
            certValues = new IdAaEtsCertValues(element);
            return certValues.getCertValues();
        } catch (SignatureAttributeNotFoundException e) {
            Application.logger.log(Level.SEVERE, "Atributo não encontrado na assinatura", e);
        } catch (CertValuesException e) {
            Application.logger.log(Level.SEVERE, "Erro no atributo CertValues", e);
        } 

        return null;
    }

    /**
     * Retorna a lista de CRLs do atributo {@link IdAaEtsRevocationValues}
     * @param signature A assinatura que contém o atributo
     * @return A lista de CRLs
     */
    public List<X509CRL> getSignatureRevocationValues(CadesSignature signature) {
        IdAaEtsRevocationValues idAaEtsRevocationValues = null;
        
        try {
            Attribute attribute = signature.getEncodedAttribute(IdAaEtsRevocationValues.IDENTIFIER);
            idAaEtsRevocationValues = new IdAaEtsRevocationValues(attribute);
        } catch (SignatureAttributeNotFoundException e) {
            Application.logger.log(Level.SEVERE, "Atributo não encontrado na assinatura", e);
        } catch (SignatureAttributeException e) {
            Application.logger.log(Level.SEVERE, "Erro no atributo RevocationValues", e);
        }

        return idAaEtsRevocationValues.getCrlValues();
    }

    /**
     * Verifica a integridade da assinatura
     * @param report O relatório de verificação da assinatura
     * @return Indica se a assinatura é íntegra
     */
    private boolean verifySignIntegrity(SignatureReport report) {
        boolean integrity = false;

        try {
            integrity = this.signature.verify(this.signerCert, report);
        } catch (VerificationException e) {
            this.exceptions.add(e);
        } catch (NullPointerException e) {
            this.exceptions.add(new PbadException(PbadException.INVALID_SIGNATURE));
        }

        return integrity;

    }
}
