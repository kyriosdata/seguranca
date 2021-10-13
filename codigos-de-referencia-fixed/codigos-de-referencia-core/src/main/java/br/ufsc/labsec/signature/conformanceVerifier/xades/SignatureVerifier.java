/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.exceptions.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateValidation.ValidationResult;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.PaReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport.Form;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignaturePolicy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.ExternalSignedData;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SigningPeriod;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.AttributeMap;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.TimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertificationPolicyException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.LpaException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureConformityException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureVerifierException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignerCertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.UnknowAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XadesSchemaException;
import org.xml.sax.SAXParseException;

/**
 * Esta classe é responsável por verificar uma assinatura.
 * Estende {@link AbstractVerifier}.
 */
public class SignatureVerifier extends AbstractVerifier {

	/**
	 * Política de assinatura
	 */
    protected SignaturePolicyInterface signaturePolicy;
	/**
	 * Bytes do conteúdo assinado
	 */
	protected byte[] bytesOfSignedContent;

    /**
     * Índice da restrição de algoritmo na política que a assinatura segue.
	 * O valor desta variável indica qual é a restrição de algoritmo
	 * na lista de restrições
     */
    private int algorithmConstraintIndex = Integer.MAX_VALUE;

    /**
     * Constrói um {@link SignatureVerifier} a partir da assinatura a ser
     * verificada e da política de assinatura usada na assinatura.
     * @param signature A assinatura XAdES a ser verificada
     * @param xadesSignatureComponent A política de assinatura
     * @throws SignatureVerifierException Exceção caso a assinatura seja nula
     */
    public SignatureVerifier(XadesSignature signature, XadesSignatureComponent xadesSignatureComponent) throws SignatureVerifierException {
        this.component = xadesSignatureComponent;
        this.signaturePolicy = xadesSignatureComponent.signaturePolicyInterface;
        
        initialize(signature, (SignatureVerifierParams) null);
        this.signaturePolicy.setActualPolicy(signature.getSignaturePolicyIdentifier(),
                signature.getSignaturePolicyUri(), AdESType.XAdES);

    }

    /**
     * Constrói um {@link SignatureVerifier} a partir da assinatura a ser
     * verificada
	 * @param signature A assinatura XAdES a ser verificada
	 * @param signaturePolicyInterface A política de assinatura
     * @throws SignatureVerifierException Exceção caso a assinatura seja nula
     * @throws PbadException Exceção em caso de erro na inicialização dos atributos
     */
    public SignatureVerifier(XadesSignature signature, SignaturePolicyInterface signaturePolicyInterface)
            throws SignatureVerifierException, PbadException {
        this(signature, (SignatureVerifierParams) null, signaturePolicyInterface);
    }

    /**
     * Constrói um {@link SignatureVerifier} a partir da assinatura a ser
     * verificada. Serão assumidos os parâmetros passados em <code>params</code>
     * para verificação.
     * @param signature A assinatura XAdES a ser verificada
     * @param params Os parâmetros de verificação
     * @param signaturePolicyInterface A política de assinatura
     * @throws PbadException Exceção em caso de erro na inicialização dos atributos
     * @throws SignatureVerifierException Exceção caso a assinatura seja nula
     */
    public SignatureVerifier(XadesSignature signature, SignatureVerifierParams params, SignaturePolicyInterface signaturePolicyInterface)
            throws PbadException, SignatureVerifierException {
        initialize(signature, params);
        this.signaturePolicy = signaturePolicyInterface;
        this.signaturePolicy.setActualPolicy(this.signature.getSignaturePolicyIdentifier(),
                this.signature.getSignaturePolicyUri(), AdESType.XAdES);
        AttributeMap.initialize();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Verifica todos os campos da assinatura conforme especificado na PA da
     * assinatura. Caso a assinatura não seja válida, os erros de validação
     * serão disponibilizados no método <code>getSignatureValidationErros</code>
     * .
     * <p>
     * Todas as regras de verificação da política de assinatura seram levados em
     * conta. Primeiro validando as regras para o caminho do assinante, depois
     * verificando se os atributos obrigatórios estão todos presentes na
     * assinatura, para então verificar a validade de cada atributo e por fim
     * verificar a integridade da assinatura.
	 *
	 * O resultado da verificação é adicionado ao relatório dado.
     * @param sigReport O relatório de verificação da assinatura
     * @return Indica se a assinatura é válida
     */
    public boolean verify(SignatureReport sigReport) {
        // TODO - Add validation results
        if (this.getTimeReference() == null) {
            this.setTimeReference(new Time(SystemTime.getSystemTime()));
        }

        try {
            if (verifySchema()) {
                sigReport.setSchema(SignatureReport.SchemaState.VALID);
            }
        } catch (XadesSchemaException e) {
            Application.logger.log(Level.WARNING, "Problema de conexão ao " +
                    "obter o schema.", e);
            sigReport.setSchema(SignatureReport.SchemaState.INDETERMINATE);
            sigReport.setSchemaMessage(e.getMessage());
        } catch (SAXException | IOException e) {
        	Application.logger.log(Level.WARNING, "Estrutura incorreta.", e.getMessage());
            sigReport.setSchema(SignatureReport.SchemaState.INVALID);
            sigReport.setSchemaMessage(e.getMessage());
        }

        this.exceptions = new ArrayList<PbadException>();
        List<PbadException> warnings = new ArrayList<PbadException>();
        try {
            this.setSignerCert();
        } catch (SignerCertificationPathException signerCertificationPathException) {
            // throw new
            // VerificationException(signerCertificationPathException);
        }

        if (this.signerCert != null) {
            sigReport.setSignerSubjectName(this.signerCert.getSubjectX500Principal().toString());
        } else {
            sigReport.setSignerSubjectName("Assinante desconhecido");
        }

        try {
            sigReport.setSignatureType(this.signature.getMode().name());
        } catch (SignatureModeException e) {
            Application.logger.log(Level.WARNING, e.getMessage());
        }
        
        sigReport.setRequiredRules(this.signaturePolicy.getMandatedSignedAttributeList().toString());
        sigReport.setProhibitedRules("not implemented");
        sigReport.setPresent(true);
        sigReport.setForm(Form.SigningCertificate);
		sigReport.setCertificatesRequiredOnSignature(this.signaturePolicy.getMandatedCertificateInfo());

        List<String> signatureAttributeList = this.signature.getAttributeList();
        List<String> mandatedSignedAttributeList = this.signaturePolicy.getMandatedSignedAttributeList();
        List<String> mandatedUnsignedAttributeList = this.signaturePolicy.getMandatedUnsignedVerifierAttributeList();
        /* Verifica se a assinatura contem todos os atributos obrigatórios */
        this.verifyPresenceOfMandatedAttributes(signatureAttributeList, mandatedSignedAttributeList, mandatedUnsignedAttributeList,
                sigReport);

        /* Faz a validação dos carimbos do tempo */
        List<TimeStamp> timeStamps = null;
        try {
            timeStamps = this.getOrderedTimeStamps();
            warnings = this.verifySignatureTimestamps(warnings, timeStamps, sigReport);
        } catch (EncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (SignatureAttributeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnknowAttributeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (PbadException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try {
            this.certPath = this.component.certificateValidation.generateCertPath(this.signerCert, this.signaturePolicy.getSigningTrustAnchors(), getTimeReference());
        } catch (Throwable e) {
            Application.logger.log(Level.WARNING, "Não foi possível obter o certificado do assinante", e);
        }

        this.checkPolicyConstraints(this.exceptions);
        List<String> attributesAlreadyVerified = this.getTimeStampPriorityList();
        List<String> mandatedAttributes = new ArrayList<String>();
        mandatedAttributes.addAll(mandatedSignedAttributeList);
        mandatedAttributes.addAll(mandatedUnsignedAttributeList);
        /* Faz a validação de cada atributo restante */
        this.verifyAttributesInMandatedList(warnings, this.exceptions, signatureAttributeList, mandatedAttributes,
                attributesAlreadyVerified, sigReport);

        try {
            this.verifyUnmandatedAttributes(sigReport);
        } catch (SignatureAttributeException e) {
            Application.logger.log(Level.SEVERE, "Erro ao validar os atributos opcionais", e);
        }

        /* Valida o caminho de certificação do assinante */
        ValidationResult validationResult = this.component.certificateValidation.validate(this.signerCert,
                this.signaturePolicy.getSigningTrustAnchors(), this.signaturePolicy.getSignerRevocationReqs(), this.getTimeReference(), sigReport);
        
		if(validationResult.getRevocationDate() != null && !sigReport.getStamps().isEmpty()) {
			Date revDate = validationResult.getRevocationDate();
			Time timeStampDate = getTemporaryTimeReference();
			if (timeStampDate == null) {
			    timeStampDate = getTimeReference();
			}

			int last = sigReport.getStamps().size() - 1;
			if(timeStampDate.before(revDate)  && sigReport.getStamps().get(last).isValid()) {
			    validationResult = ValidationResult.valid;
			    validationResult.setMessage("Certificado revogado, porém valido na data do Carimbo do Tempo.");
			}
		}
        
        sigReport.verifyValidationResult(validationResult);
        this.exceptions.add(new PbadException(validationResult.getMessage()));
        
        /* Verifica a assinatura, se isso fizer sentido */
        this.verifySignatureIntegrity(sigReport);
        /* Não ocorreram erros ao validar a assinatura? */
        boolean isValid = this.exceptions.size() == 0;
        /* Atualiza a lista de erros */
        this.exceptions.addAll(warnings);
        this.setTimeReference(this.getTimeReference());
        return isValid;

    }

	/**
	 * Verifica o esquema XML da assinatura
	 * @return Indica se o esquema é válido
	 * @throws SAXException Exceção em caso de falha na manipulação do esquema
	 * @throws IOException Exceção em caso de erro na manipulação da assinatura
	 * @throws XadesSchemaException Exceção em caso de erro na obtenção do esquema
	 */
	protected boolean verifySchema() throws SAXException, IOException, XadesSchemaException {

		boolean valid = false;
		Source xadesSchema = null, xmlDSigSchema = null;

		String xadesSchemaPath = this.component.getApplication().getComponentParam(
				this.component, "xadesSchema");
		String xmlDSigSchemaPath = this.component.getApplication().getComponentParam(
				this.component, "xmlDsigSchema");

		InputStream xadesSchemaTemp = Application.class.getResourceAsStream("/" + xadesSchemaPath);
		InputStream xmlDSigSchemaTemp = Application.class.getResourceAsStream("/" + xmlDSigSchemaPath);

		if (xadesSchemaTemp != null) {
			xadesSchema = new StreamSource(xadesSchemaTemp);
		} else {
			try {
				xadesSchema = new StreamSource(new FileInputStream(xadesSchemaPath));
			} catch (FileNotFoundException e) {
				Application.logger.log(Level.SEVERE,
						"Não foi possível encontrar o schema Xades.", e);
			}
		}

		if (xmlDSigSchemaTemp != null) {
			xmlDSigSchema = new StreamSource(xmlDSigSchemaTemp);
		} else {
			try {
				xmlDSigSchema = new StreamSource(new FileInputStream(xmlDSigSchemaPath));
			} catch (FileNotFoundException e) {
				Application.logger.log(Level.SEVERE,
						"Não foi possível encontrar o schema de assinatura XML.", e);
			}
		}

		Source[] schemas = { xmlDSigSchema, xadesSchema };
        Schema combinedSchema;
        try {
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            combinedSchema = factory.newSchema(schemas);
        } catch (SAXParseException e) {
            throw new XadesSchemaException(XadesSchemaException.CONNECTION_DISRUPTED, e);
        }

		if (combinedSchema != null) {
			Validator validator = combinedSchema.newValidator();

			XadesSignature signature = (XadesSignature) this.getSignature();
			Source source = new DOMSource(signature.getSignatureElement());

			validator.validate(source);
			valid = true;
		}

		return valid;

	}

    /**
     * Verifica a integridade da assinatura e adiciona os resultados ao relatório
     * @param sigReport O relatório de verificação da assinatura
     */
    private void verifySignatureIntegrity(SignatureReport sigReport) {
        try {
            if (!this.verifySignature(sigReport)) {
                this.exceptions.add(new PbadException(PbadException.INVALID_SIGNATURE));
            }
        } catch (VerificationException verifyException) {
            this.exceptions.add(verifyException);
        }
    }

    /**
     * Verifica os carimbos de tempo em ordem de tempo e atualiza a referência
     * de tempo conforme a validação é executada. O resultado é adicionado
	 * ao relatório de verificação.
     * @param warnings A lista de mensagens de alerta
     * @param timeStamps A lista de carimbos de tempo
     * @param sigReport O relatório de verificação da assinatura
     * @return Uma lista de mensagens de alerta
     * @throws PbadException Exceção em caso de falha na obtenção das informações de um carimbo
     */
    private List<PbadException> verifySignatureTimestamps(List<PbadException> warnings, List<TimeStamp> timeStamps,
            SignatureReport sigReport) throws PbadException {
        ArrayList<PbadException> insideWarnings = new ArrayList<PbadException>();
        String errorMessage = null;
        if (timeStamps.size() > 0) {
            boolean isAtLastOneValid = false;
            boolean isAtLeastOneExpired = false;
            boolean isAtLeastOneInvalid = false;
            for (TimeStamp timeStamp : timeStamps) {

                String actualIdentifier = timeStamp.getIdentifier();
                boolean isMandated = this.signaturePolicy.getMandatedSignedAttributeList().contains(actualIdentifier)
                        || this.signaturePolicy.getMandatedUnsignedVerifierAttributeList().contains(actualIdentifier);
                TimeStampReport timeStampReport = new TimeStampReport();
                AttribReport attribReport = new AttribReport();
                attribReport.setAttribName(actualIdentifier);
                try {
                    timeStamp.validate(timeStampReport, timeStamps);
                    if (timeStampReport.getCertPathState().equals(SignatureReport.CertValidity.Expired.toString())) {
                        errorMessage = timeStampReport.getCertPathMessage();
                        insideWarnings.add(new SignatureAttributeException(errorMessage));
                        sigReport.addTimeStampReport(timeStampReport);
                        attribReport.setError(true);
                    } else {
                        isAtLastOneValid = true;
                        sigReport.addTimeStampReport(timeStampReport);
                        attribReport.setError(false);
                        //this.setTimeReference(timeStamp.getTimeReference());
                    }
                } catch (NotInICPException notInICPException) {
                    errorMessage = notInICPException.getMessage();
                    attribReport.setError(AttribReport.HasBeenValidated.NOT_VALIDATED);
                    isAtLeastOneInvalid = true;
                } catch (TimeStampExceptionAbstract timeStampException) {
                    if (!(timeStampException.getProblems() != null &&
                            timeStampException.getProblems().size() == 1 &&
                            timeStampReport.getCertPathState().equals
                                    (SignatureReport.CertValidity.Expired.toString()))) {
                        isAtLeastOneInvalid = true;
                    } else {
                        isAtLeastOneExpired = true;
                    }
                    insideWarnings.add(timeStampException);
                    errorMessage = timeStampException.getMessage();
                    sigReport.addTimeStampReport(timeStampReport);
                    attribReport.setError(true);
                } catch (SignatureAttributeException signatureAttributeException) {
                    insideWarnings.add(signatureAttributeException);
                    errorMessage = signatureAttributeException.getMessage();
                    sigReport.addTimeStampReport(timeStampReport);
                    attribReport.setError(true);
                    isAtLeastOneInvalid = true;
                } catch (Throwable t) {
                    t.printStackTrace();
                    errorMessage = t.getMessage();
                    sigReport.addTimeStampReport(timeStampReport);
                    attribReport.setError(true);
                    isAtLeastOneInvalid = true;
                }finally {
                    if(!actualIdentifier.equals(SignatureTimeStamp.IDENTIFIER)) {
                        this.setTimeReference(timeStamp.getTimeReference());
                    } else {
                        this.setTemporaryTimeReference(timeStamp.getTimeReference());
                    }
                    if (errorMessage != null) {
                        attribReport.setErrorMessage(errorMessage);
                        errorMessage = null;
                    }
                    if (isMandated) {
                        sigReport.addAttribRequiredReport(attribReport);
                    } else {
                        sigReport.addAttribOptionalReport(attribReport);
                    }
                }
            }
            if (!isAtLastOneValid) {
                this.exceptions.addAll(insideWarnings);
                insideWarnings = new ArrayList<PbadException>();
                // When there is not a valid timestamp, today's date is used
                this.setTimeReference(new Time(SystemTime.getSystemTime()));
            }

            sigReport.setHasOneValidTimeStamp(isAtLastOneValid);
            sigReport.setHasOneExpiredTimeStamp(isAtLeastOneExpired);
            sigReport.setHasOneInvalidTimeStamp(isAtLeastOneInvalid);
        }
        return insideWarnings;
    }

    /**
     * Verifica a presença de atributos obrigatórios. O resultado é adicionado
	 * ao relatório
     * @param signatureAttributeList Lista dos identificadores de atributos da assinatura
     * @param mandatedSignedAttributeList Lista de atributos assinados obrigatórios à assinatura
     * @param mandatedUnsignedAttributeList Lista de atributos não-assinados obrigatórios à assinatura
     * @param sigReport O relatório de verificação da assinatura
     */
    private void verifyPresenceOfMandatedAttributes(List<String> signatureAttributeList, List<String> mandatedSignedAttributeList,
            List<String> mandatedUnsignedAttributeList, SignatureReport sigReport) {
        for (String mandatedAttribute : mandatedSignedAttributeList) {
            if (!signatureAttributeList.contains(mandatedAttribute)) {
                this.exceptions.add(new SignatureAttributeNotFoundException(
                        SignatureAttributeNotFoundException.MISSING_MANDATED_SIGNED_ATTRIBUTE, mandatedAttribute));
                AttribReport attribReport = new AttribReport();
                attribReport.setAttribName(mandatedAttribute);
                attribReport.setError(true);
                attribReport.setErrorMessage(new SignatureAttributeNotFoundException(
                        SignatureAttributeNotFoundException.MISSING_MANDATED_SIGNED_ATTRIBUTE, mandatedAttribute).getMessage());
                sigReport.addAttribRequiredReport(attribReport);
            }
        }
        for (String mandatedAttribute : mandatedUnsignedAttributeList) {
            if (!signatureAttributeList.contains(mandatedAttribute)) {
                SignatureAttributeNotFoundException sigAttributeNotFoundException = new SignatureAttributeNotFoundException(
                        SignatureAttributeNotFoundException.MISSING_MANDATED_UNSIGNED_ATTRIBUTE, mandatedAttribute);
                sigAttributeNotFoundException.setCritical(false);
                this.exceptions.add(sigAttributeNotFoundException);
                AttribReport attribReport = new AttribReport();
                attribReport.setAttribName(mandatedAttribute);
                attribReport.setError(true);
                attribReport.setErrorMessage(new SignatureAttributeNotFoundException(
                        SignatureAttributeNotFoundException.MISSING_MANDATED_UNSIGNED_ATTRIBUTE, mandatedAttribute).getMessage());
                sigReport.addAttribRequiredReport(attribReport);
            }
        }

        boolean hasAttributeExceptions = !exceptions.isEmpty();
		sigReport.setPresenceOfInvalidAttributes(hasAttributeExceptions);

    }

    /**
     * Verifica os atributos opcionais presentes na assinatura.
     * 
     * @return {@link List}<{@link PbadException}>
     * 
     * @throws SignatureAttributeException
     */

	/**
	 * Realiza a verificação de atributos não-obrigatórios presentes na assinatura
	 * @param sigReport O relatório de verificação da assinatura
	 * @return Uma lista de mensagens de erro da verificação
	 * @throws SignatureAttributeException Exceção em caso de erro na manipulação dos atributos
	 */
	public List<PbadException> verifyUnmandatedAttributes(SignatureReport sigReport) throws SignatureAttributeException {
        List<String> mandatedSignedAttributeList = this.signaturePolicy.getMandatedSignedAttributeList();
        List<String> mandatedUnsignedAttributeList = this.signaturePolicy.getMandatedUnsignedVerifierAttributeList();
        List<String> signatureAttributeList = this.signature.getAttributeList();
        List<String> attributesAlreadyVerified = this.getTimeStampPriorityList();
        List<String> mandatedAttributes = new ArrayList<String>();
        mandatedAttributes.addAll(mandatedSignedAttributeList);
        mandatedAttributes.addAll(mandatedUnsignedAttributeList);
        return this.verifyOnlyUnmandatedAttributes(signatureAttributeList, mandatedAttributes, attributesAlreadyVerified, sigReport);
    }

    /**
     * Retorna a lista dos erros que ocorreram na última validação
     * @return A lista de erros
     */
    public List<PbadException> getSignatureValidationErrors() {
        List<PbadException> resulting = null;
        if (this.exceptions != null) {
            resulting = new ArrayList<PbadException>(this.exceptions);
        } else {
            resulting = new ArrayList<PbadException>();
        }
        return resulting;
    }

    /**
     * Retorna os bytes do conteúdo assinado que foram passados no método
     * <code> setSignedContent(byte[] signedContent) </code>
     * @return Os bytes do conteúdo assinado
     */
    public byte[] getSignedContent() {
        return this.bytesOfSignedContent;
    }

    /**
     * Retorna a assinatura que foi passada na construção da classe
     * @return A assinatura a ser verificada
     */
    public XadesSignature getSignature() {
        return this.signature;
    }

    /**
     * Retorna a Política de Assinatura da assinatura passada na construção
     * desta classe.
     * @return A política de assinatura
     */
    public SignaturePolicyInterface getSignaturePolicy() {
        return signaturePolicy;
    }

    /**
     * Verifica regras da política de assinatura que não são especificas de
     * apenas um atributo, mas tem um contexto global, como por exemplo
     * restrições de algortimos.
     * @param exceptions Lista de erros da verificação
     */
    protected void checkPolicyConstraints(List<PbadException> exceptions) {
        try {
            this.checkExternalSignedData();
        } catch (PbadException signatureException) {
            exceptions.add(signatureException);
        }
        try {
            this.checkSignaturePolicyPeriod();
        } catch (SignatureAttributeException signatureAttributeException) {
            exceptions.add(signatureAttributeException);
        } catch (EncodingException encodingException) {
            exceptions.add(encodingException);
        }
        /*
         * Caso não tenha sido possível construir o caminho de certificação,
         * também não é possível verificar as políticas de certificação
         * aceitáveis
         */
        if (this.certPath != null && this.certPath.getCertificates().size() > 0) {
            try {
                this.checkAcceptablePolicies();
            } catch (CertificationPolicyException certificationPolicyException) {
                exceptions.add(certificationPolicyException);
            } catch (CertificationPathException certificationPathException) {
                exceptions.add(certificationPathException);
            }
        }
        if (!this.checkAlgorithmsConstraints()) {
            exceptions.add(new SignatureConformityException(SignatureConformityException.INVALID_ALGORITHM));
        }
        if (!this.checkKeyLength()) {
            exceptions.add(new SignatureConformityException(SignatureConformityException.INVALID_SIZE_KEY));
        }
    }

    /**
     * Verifica se o algoritmo especificado na Política de Assinatura é o mesmo
     * usado na assinatura.
     * @return Indica se os identificadores dos algoritmos de hash são os mesmos
     */
    protected boolean checkAlgorithmsConstraints() {
        String[] signatureMethods = this.signaturePolicy.getSignatureAlgorithmIdentifierSet();
        if (signatureMethods[0].equals("")) {
            return true;
        }

        XadesSignature signature = this.signature;
        Element signatureElement = signature.getSignatureElement();
        NodeList nodeListSignatureMethod = signatureElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureMethod");
        for (int i = 0; i < signatureMethods.length; i++) {
            if (nodeListSignatureMethod.item(0).getAttributes().getNamedItem("Algorithm").getTextContent().equals(signatureMethods[i])) {
                this.algorithmConstraintIndex = i;
                return true;
            }
        }

        return false;
    }

    /**
     * Percorre o caminho de certificação verificando se as políticas usadas
     * para cada certificado se encontram dentro das permitidas pela política de
     * assinatura.
     * @throws CertificationPathException Exceção em caso de erro no caminho de certificação
     */
    protected void checkAcceptablePolicies() throws CertificationPathException {
        @SuppressWarnings("unchecked")
        List<X509Certificate> certPathCertificates = (List<X509Certificate>) this.certPath.getCertificates();
        X509Certificate lastCa = certPathCertificates.get(certPathCertificates.size() - 1);
        CertificateTrustPoint trustPoint = this.signaturePolicy.getTrustPoint(lastCa.getIssuerX500Principal());
        // FIXME -- Corrigir com novo componente
        // checkAcceptablePolicies(trustPoint);
    }

    /**
     * Checa se o tamanho da chave usada para assinar é compatível com o tamanho
     * mínimo exigido pela PA.
     * @return Indica se o tamanho da chave do assinante é igual ou maior que o exigido
     */
    protected boolean checkKeyLength() {
        boolean lengthIsAcceptable = false;

        XadesSignature xmlSignature = this.signature;
        NodeList nodeListSignatureValue = xmlSignature.getSignatureElement().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
                "SignatureValue");
        byte[] signatureValueBytes = null;
        try {
            signatureValueBytes = Base64.decode(nodeListSignatureValue.item(0).getTextContent().getBytes());
        } catch (Exception e) {
            new SignatureConformityException(e.getMessage());
        }
        if (this.algorithmConstraintIndex != Integer.MAX_VALUE) { // há alguma restrição de algoritmo que a assinatura segue
            int[] minKeySet = this.signaturePolicy.getMinKeyLengthSet();
            lengthIsAcceptable = signatureValueBytes.length * 8 >= minKeySet[this.algorithmConstraintIndex];
        }

        return lengthIsAcceptable;
    }

    /**
     * Verifica se a assinatura foi feita dentro do período válido para o uso de
     * políticas
     * @return Indica se a assinatura está dentro do período válido
     *         para o uso de políticas
     * @throws SignatureAttributeException Exceção em caso de erro na manipulação de atributos
     * @throws EncodingException
     */
    protected boolean checkSignaturePolicyPeriod() throws SignatureAttributeException, EncodingException {
        boolean result = true;
        SigningPeriod signaturePeriod = this.signaturePolicy.getSigningPeriod();
        Time estimatedSignatureCreation = this.getTimeReference();
        if (signaturePeriod == null) {
            result = false;
        } else {
            if (estimatedSignatureCreation.before(signaturePeriod.getNotBefore())
                    || estimatedSignatureCreation.after(signaturePeriod.getNotAfter())) {
                result = false;
            }
        }
        return result;
    }

    /**
     * Verifica se a assinatura está respeitando a regra da política de
     * assinatura sobre o dado assinado ser interno, externo ou indiferente.
     * @return Indica se a assinatura está de acordo com a política
     * @throws PbadException
     */
    protected boolean checkExternalSignedData() throws PbadException {
        boolean result;
        ExternalSignedData externalData = this.signaturePolicy.getExternalSignedData();
        if (externalData == ExternalSignedData.EXTERNAL) {
            result = this.signature.isExternalSignedData();
        } else if (externalData == ExternalSignedData.INTERNAL) {
            result = !this.signature.isExternalSignedData();
        } else
            result = true;
        return result;
    }

    /**
     * Verifica a assinatura e adiciona os resultados ao relatório
     * @param sigReport O relatório de verificação da assinatura
     * @return Indica se a assinatura está válida
     * @throws VerificationException Exceção em caso de erro durante a verificação
     */
    protected boolean verifySignature(SignatureReport sigReport) throws VerificationException {
        /*
         * O primeiro certificado do caminho sempre corresponde ao certificado
         * do assinante
         */
        X509Certificate signerCertificate = this.getSignerCertificate();
        boolean valid = this.signature.verify(signerCertificate, sigReport);
        sigReport.setAsymmetricCipher(valid);
        return valid;
    }

    /**
     * Retorna uma lista com todos os atributos de Carimbo do Tempo existentes
     * na assinatura que foram referenciados na lista de prioridade. Passa por
     * todos os atributos da assinatura, instanciando e adicionando na lista de
     * retorno aqueles que tem um identificador referenciado na lista de
     * prioridade
     * @return A lista de carimbos de tempo
     * @throws SignatureAttributeException Exceção em caso de erro nos atributos da assinatura
     * @throws UnknowAttributeException Exceção em caso de atributo desconhecido
     */
    private List<TimeStamp> getTimeStamps() throws SignatureAttributeException, UnknowAttributeException {
        List<String> completeAttributeList = this.getSignature().getAttributeList();
        Map<String, Integer> indexes = new HashMap<String, Integer>();
        List<TimeStamp> timeStampList = new ArrayList<TimeStamp>();
        TimeStamp timeStampInstance = null;
        List<String> timeStampPriorityList = this.getTimeStampPriorityList();
        for (String identifier : completeAttributeList) {
            if (timeStampPriorityList.contains(identifier)) {
                if (!indexes.containsKey(identifier)) {
                    indexes.put(identifier, 0);
                }
                Class<?> attributeClass = null;
                Constructor<?> constructor = null;
                attributeClass = AttributeMap.getAttributeClass(identifier);
                if (attributeClass == null) {
                    throw new UnknowAttributeException(UnknowAttributeException.UNKNOW_ATTRIBUTE, identifier);
                }
                try {
                    constructor = attributeClass.getConstructor(new Class<?>[] { AbstractVerifier.class, Integer.class });
                } catch (SecurityException securityException) {
                    throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + identifier,
                            securityException.getStackTrace());
                } catch (NoSuchMethodException noSuchMethodException) {
                    throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + identifier,
                            noSuchMethodException.getStackTrace());
                }
                try {
                    timeStampInstance = (TimeStamp) constructor.newInstance(this, indexes.get(identifier));
                } catch (IllegalArgumentException illegalArgumentException) {
                    illegalArgumentException.printStackTrace();
                    throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + identifier,
                            illegalArgumentException.getStackTrace());
                } catch (InstantiationException illegalArgumentException) {
                    illegalArgumentException.printStackTrace();
                    throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + identifier,
                            illegalArgumentException.getStackTrace());
                } catch (IllegalAccessException illegalArgumentException) {
                    illegalArgumentException.printStackTrace();
                    throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + identifier,
                            illegalArgumentException.getStackTrace());
                } catch (InvocationTargetException illegalArgumentException) {
                    illegalArgumentException.printStackTrace();
                    throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + identifier,
                            illegalArgumentException.getStackTrace());
                }
                int counter = indexes.get(identifier);
                counter++;
                indexes.put(identifier, counter);
                timeStampList.add(timeStampInstance);
            }
        }
        return timeStampList;
    }

    /**
     * Retorna uma lista de atributos de Carimbo do Tempo (aqueles referenciados
     * na lista de prioridade) ordenada por identificador, de acordo com o
     * especificado na lista de prioridade, e com cada grupo de mesmo
     * identificador ordenado por tempo (TimeReference). Na ordenação por tempo,
     * é considerado que o tempo mais recente (ou seja, maior) tem maior
     * prioridade.
     * @return A lista de carimbos de tempo ordenada de acordo
     * @throws EncodingException
	 * @throws SignatureAttributeException Exceção em caso de erro nos atributos da assinatura
	 * @throws UnknowAttributeException Exceção em caso de atributo desconhecido
     */
    @SuppressWarnings("unchecked")
    public List<TimeStamp> getOrderedTimeStamps() throws EncodingException, SignatureAttributeException, UnknowAttributeException {
        List<TimeStamp> disorderedTimeStampList = this.getTimeStamps();
        List<TimeStamp> timeStampListSortedByIdentifier = this.getTimeStampListSortedByIdentifier(disorderedTimeStampList);
        List<TimeStamp> timeStampListSortedByIdentifierAndTime = new ArrayList<TimeStamp>();
        List<TimeStamp> timeStampSeparatedByIdentifier = new ArrayList<TimeStamp>();
        while (timeStampListSortedByIdentifier.size() != 0) {
            TimeStamp timeStamp = timeStampListSortedByIdentifier.get(0);
            String identifier = timeStamp.getIdentifier();
            timeStampSeparatedByIdentifier.add(timeStamp);
            timeStampListSortedByIdentifier.remove(timeStamp);
            boolean sameIdentifier = true;
            while (timeStampListSortedByIdentifier.size() != 0 && sameIdentifier) {
                TimeStamp nextTimeStamp = timeStampListSortedByIdentifier.get(0);
                sameIdentifier = identifier.equals(nextTimeStamp.getIdentifier());
                if (sameIdentifier) {
                    timeStampSeparatedByIdentifier.add(nextTimeStamp);
                    timeStampListSortedByIdentifier.remove(nextTimeStamp);
                }
            }
            if (timeStampSeparatedByIdentifier.size() > 1) {
                Collections.sort(timeStampSeparatedByIdentifier);
            }
            timeStampListSortedByIdentifierAndTime.addAll(timeStampSeparatedByIdentifier);
            timeStampSeparatedByIdentifier.clear();
        }
        return timeStampListSortedByIdentifierAndTime;
    }

    /**
     * Ordena a lista de carimbos do tempo de acordo com seu identificador, na
     * ordem estabelecida na lista de prioridades.
     * @param disorderedTimeStampList A lista de Carimbos do Tempo a ser ordenada
     * @return A lista de carimbos ordenada
     */
    private List<TimeStamp> getTimeStampListSortedByIdentifier(List<TimeStamp> disorderedTimeStampList) {
        List<TimeStamp> timeStampListSortedByIdentifier = new ArrayList<TimeStamp>();
        List<String> timeStampPriorityList = this.getTimeStampPriorityList();
        for (String priorityIdentifier : timeStampPriorityList) {
            for (TimeStamp timeStamp : disorderedTimeStampList) {
                String identifier = timeStamp.getIdentifier();
                if (identifier.compareTo(priorityIdentifier) == 0) {
                    timeStampListSortedByIdentifier.add(timeStamp);
                }
            }
        }
        return timeStampListSortedByIdentifier;
    }

	/**
	 * Retorna o relatório da verificação da política de assinatura
	 * @return O relatório da verificação da política de assinatura
	 * @throws SignatureAttributeException Exceção em caso de erro nos atributos da assinatura
	 * @throws EncodingException
	 */
	public PaReport getPaReport() throws SignatureAttributeException, EncodingException {
		PaReport report = this.signaturePolicy.getReport();
		report.setPaExpired(!checkSignaturePolicyPeriod());
		return report;
	}

    
    
	
}
