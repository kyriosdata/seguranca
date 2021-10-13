package br.ufsc.labsec.signature.conformanceVerifier.cades;

/*

 Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
 da Universidade Federal de Santa Catarina (UFSC).

 Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.ocsp.OCSPResp;

import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.AttributeMap;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSignerAttr;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureVerifierException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerCertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.TACException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.UnknowAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.exceptions.VerificationException;

/**
 * Esta classe trata as partes de verificação comuns entre assinaturas CAdES e
 * carimbos do tempo.
 */
public abstract class AbstractVerifier {
	
    /**
     * Assinatura a ser verificada
     */
    protected CadesSignature signature;
//    /**
//     * Repositório de certificados que serão usados na validação
//     */
    // protected CertStore certStore;
    /**
     * Caminho de certificação do assinante
     */
    protected CertPath certPath;
    /**
     * Certificado da autoridade de OCSP
     */
    protected X509Certificate ocspServerCertificate;
    /**
     * Lista de erros de validação
     */
    protected List<PbadException> exceptions;
    /**
     * Repositório de respostas OCSP
     */
    protected List<OCSPResp> ocspRespList;
    /**
     * Certificado do assinante
     */
    protected X509Certificate signerCert;
    /**
     * Tempo que será levado em conta para validar a assinatura
     */
    private Time timeReference;
    /**
     * Tempo que será levado em conta para validar a assinatura
     */
    private Time temporaryTimeReference; //FIXME melhorar o nome desta variavel 
    /**
     * Parâmetro de validação da assinatura
     */
    private SignatureVerifierParams params;
	/**
	 * Componente de assinautra CAdES
	 */
	protected CadesSignatureComponent component;
	/**
	 * Indica se a assinatura a ser verificada é um carimbo de tempo
	 */
    private boolean isTimeStamp;

	/**
	 * Inicializa os valores de atributos da classe
	 * @param signature A assinatura a ser verificada
	 * @param params Os parâmetros de validação
	 * @param isTimeStamp Indica se a assinatura a ser verificada é um carimbo de tempo
	 * @throws SignatureVerifierException
	 */
    public void initialize(CadesSignature signature, SignatureVerifierParams params, boolean isTimeStamp) throws SignatureVerifierException {
        if (params == null) {
            this.params = new SignatureVerifierParams();
        } else {
            this.params = params;
        }
        if (signature == null) {
            throw new SignatureVerifierException(SignatureVerifierException.SIGNATURE_NULL);
        }

        this.signature = signature;
        this.isTimeStamp = isTimeStamp;

        // TODO - Adicionar buscas no SignaturePoxy por atributos obrigatórios e
        // no CertificateCollection/RevocationInformation para montar um
        // certStore
    }
    
    
    /**
     * Método para inicializar um CAdES Verifier
     * 
     * */
    public void initialize(CadesSignature signature, SignatureVerifierParams param) throws SignatureVerifierException {
    	initialize(signature, param, false);
    }
    /**
     * Os atributos da assinatura que tem o seu identificador presente na lista
     * de atributos obrigatórios passados aqui serão verificados.
     * 
     * Na lista <code>errors</code> serão retornados os erros que comprometem a
     * assinatura, já na lista de <code>warnings</code> seram retornados os
     * erros que aconteceram mas não infuenciam na validade da assinatura.
     * 
     * Os atributos que tem seu identificador presente na lista
     * attributesToExclude não serão verificados mesmo que presentes na lista de
     * atributos obrigatórios.
	 *
	 * O resultado da verificação será adicionado ao relatório dado.
     * 
     * @param warnings - Lista de alertas. Irá ser atualizada com a lista de erros, que poderão
     *            ocorrer ao validar a assinatura, mas que não a tornam inválida
     * @param exceptions2 Lista de erros da verificação. Será atualizada com a lista de erros
	 *                    que tornam a assinatura inválida
     * @param signatureAttributeList Lista de atributos presentes na
     *            assinatura que devem ser levados em conta
     * @param mandatedAttributeList Lista de atributos que devem ser
     *            considerados obrigatórios
     * @param attributesToExclude Lista de atributos que devem ser
     *            desconsiderados
     * @param sigReport O relatório da verificação da assinatura
     */
    protected void verifyAttributesInMandatedList(List<PbadException> warnings, List<PbadException> exceptions2,
            List<String> signatureAttributeList, List<String> mandatedAttributeList, List<String> attributesToExclude,
            SignatureReport sigReport) {
        boolean isMandated = true;
        Map<String, Integer> identifierToCounter = new HashMap<String, Integer>();
        Map<String, List<PbadException>> identifierToErrors = new HashMap<String, List<PbadException>>();
        for (String attributeId : signatureAttributeList) {
            if (mandatedAttributeList.contains(attributeId)) {
                if (!attributesToExclude.contains(attributeId)) {
                    validateAttribute(identifierToCounter, identifierToErrors, attributeId, sigReport, isMandated);
                }
            }
        }
        /*
         * Verifica se, dentre os atributos obrigatórios, há pelo menos um
         * válido
         */
        Set<String> signatureAttributeSet = new HashSet<String>(signatureAttributeList);
        for (String attributeId : signatureAttributeSet) {
            if (mandatedAttributeList.contains(attributeId)) {
                if (!this.getTimeStampPriorityList().contains(attributeId)) {
                    Integer counter = identifierToCounter.get(attributeId);
                    List<PbadException> detectedErrors = identifierToErrors.get(attributeId);
                    if (counter.equals(detectedErrors.size())) {
                        exceptions2.addAll(detectedErrors);
                    } else {
                        warnings.addAll(detectedErrors);
                    }
                }
            }
        }
		
		sigReport.setPresenceOfInvalidAttributes(!exceptions2.isEmpty());

    }

    /**
     * Para fazer a validação o método busca a classe do atributo, e se a mesma
     * existir, ela será instanciada e seu método de validação chamado. Após a
     * execução do método o contador do atributo em questão e a sua lista de
     * erros serão atualizados.
     * @param identifierToCounter Mapa entre identificador de atributo com a
     *            quantidade de aparições desse atributo
     * @param identifierToErrors Mapa da lista de erros, que será atualizada
     *            após verificar o atributo
     * @param attributeId Identificador do atributo
     * @param sigReport O relatório da verificação da assinatura
     * @param isMandated Indica se o atributo a ser validade é obrigatório na assinatura
     */
    private void validateAttribute(Map<String, Integer> identifierToCounter, Map<String, List<PbadException>> identifierToErrors,
            String attributeId, SignatureReport sigReport, boolean isMandated) {
        Class<?> attributeClass;
        List<PbadException> attributeErrors = null;
        if (!identifierToCounter.containsKey(attributeId)) {
            identifierToCounter.put(attributeId, 0);
            attributeErrors = new ArrayList<PbadException>();
            identifierToErrors.put(attributeId, attributeErrors);
        } else {
            attributeErrors = identifierToErrors.get(attributeId);
        }
        attributeClass = AttributeMap.getAttributeClass(attributeId);
        /*
         * Se é um atributo desconhecido que é obrigatório e este não pode se
         * validado, ele invalidará a assinatura, caso não seja obrigatório o
         * erro será ignorado ao checar se a assinatura é valida ou não
         */
        this.instantiateAndCallValidate(identifierToCounter, attributeId, attributeClass, attributeErrors, sigReport, isMandated);
    }

    /**
     * Instancia e chama a validação da classe passada para o identificador
     * @param identifierToCounter Mapa de contadores de atributos verificados
     *            que será atualizada após a execução desse método
     * @param attributeId Identificador do atributo
     * @param attributeClass Objeto que representa a classe do atributo que
     *            será verificado
     * @param attributeErrors Lista de erros de validação do atributo que será
     *            atualizada após a execução desse método
     * @param sigReport O relatório da verificação da assinatura
     */
	private void instantiateAndCallValidate(Map<String, Integer> identifierToCounter,
			String attributeId, Class<?> attributeClass, List<PbadException> attributeErrors,
			SignatureReport sigReport, boolean isMandated) {

		if (attributeClass == null) {
			attributeErrors.add(new UnknowAttributeException(
					UnknowAttributeException.UNKNOW_ATTRIBUTE, attributeId));
		} else {

			int errorsBefore = attributeErrors.size();
			Constructor<?> constructor;
			AttribReport attribReport = new AttribReport();
            SignatureAttribute attributeInstance = null;

			try {

				if (!attributeId.equals("DataObjectFormat")) {
					constructor = attributeClass.getConstructor(
							new Class<?>[] { AbstractVerifier.class, Integer.class });
					attributeInstance = (SignatureAttribute) constructor
							.newInstance(this, identifierToCounter.get(attributeId));
				}

				identifierToCounter.put(attributeId, identifierToCounter.get(attributeId) + 1);
                attributeInstance.validate();

				/*
				 * A validade do atributo id-messageDigest está "amarrada" à
				 * validade da assinatura, visto que suas funcionalidades são
				 * iguais (ou muito similares).
				 */
				if (attributeId.equals(PKCSObjectIdentifiers.pkcs_9_at_messageDigest.getId())
						&& !sigReport.isHash()) {
					throw new SignatureAttributeException(SignatureAttributeException.HASH_FAILURE);
				}

			} catch (TACException e) {
				attribReport.setWarningMessage(e.getMessage());
			} catch (NoSuchMethodException | SecurityException | PbadException
					| InstantiationException | IllegalAccessException | IllegalArgumentException
					| InvocationTargetException | IOException e) {

                String errorMsg = e.getMessage() != null ? e.getMessage() :
                        e.getCause().getMessage();

                if (errorMsg.contains(SignatureAttributeException.INVALID_PA_OID)) {
                    attributeErrors.add(new SignatureAttributeException(
                            SignatureAttributeException.INVALID_PA_OID + ((IdAaEtsSigPolicyId)attributeInstance).getSignaturePolicyId(), e.getStackTrace()));
                    sigReport.setPaOidValid(false);
                } else if (errorMsg.contains("IdAaEtsSigPolicyIdentifier")) {
                    attributeErrors.add(new SignatureAttributeException(errorMsg));
                } else if (errorMsg.contains(SignatureAttributeException.WRONG_DISTINGUISHED_NAME_ORDER)) {
                    attribReport.setWarningMessage(errorMsg);
                } else {
                    attributeErrors.add(new SignatureAttributeException(
                            SignatureAttributeException
                                    .ATTRIBUTE_BUILDING_FAILURE + attributeId
                                    + " - " + errorMsg, e.getStackTrace()));
                }

			} finally {
				if (attributeErrors.size() > errorsBefore) {
                    attribReport.setError(true);
                    attribReport.setErrorMessage(
                            attributeErrors.get(attributeErrors.size() - 1).getMessage());
                }
                attribReport.setAttribName(AttributeMap.translateName(attributeId));

                if (isMandated) {
                    sigReport.addAttribRequiredReport(attribReport);
                } else {
                    sigReport.addAttribOptionalReport(attribReport);
                }
			}

		}

		String signerAttrId = AttributeMap.translateName(IdAaEtsSignerAttr.IDENTIFIER);
		for (AttribReport attr : sigReport.getOptionalAttrib()) {
			if (attr.getAttribName().equals(signerAttrId)) {
				attr.setWarningMessage("A estrutura dos atributos declarados"
						+ " do assinante não foi validada.");
			}
		}

	}

    /**
     * Verifica apenas os atributos que não são obrigatórios segundo a lista
     * passada. A lista de atributos que não devem ser verificados mesmo que não
     * sejam obrigatórios será levada em conta.
     * @param signatureAttributeList Lista de atributos da assinatura
     * @param mandatedAttributeList Lista de atributo obrigatórios, de acordo
     *            com a política de assinatura
     * @param attributesToExclude Atributos a serem ignorados
     */
    public void verifyOnlyUnmandatedAttributes(List<String> signatureAttributeList, List<String> mandatedAttributeList,
            List<String> attributesToExclude, SignatureReport sigReport) {
        boolean isMandated = false;
        Map<String, Integer> identifierToCounter = new HashMap<String, Integer>();
        Map<String, List<PbadException>> identifierToErrors = new HashMap<String, List<PbadException>>();
        for (String attributeId : signatureAttributeList) {
            if (!mandatedAttributeList.contains(attributeId)) {
                if (!attributesToExclude.contains(attributeId)) {
                    validateAttribute(identifierToCounter, identifierToErrors, attributeId, sigReport, isMandated);
                    if (!identifierToCounter.containsKey(attributeId)) {
                        identifierToCounter.put(attributeId, 0);
                    }
                }
            }
        }
    }

    /**
     * Constrói o caminho de certificação do signatário.
	 * @param trustAnchors As âncoras de confiança do caminho
     * @throws SignerCertificationPathException Exceção em caso de erro na construção do caminho de certificação
     */
    protected void buildCertPath(Set<TrustAnchor> trustAnchors) throws SignerCertificationPathException, SignatureAttributeException {
        this.setSignerCert();
        // try {
        // this.certPath = CertPathBuilder.buildPath(this.signerCert,
        // this.certStore, trustAnchors, false);
        // } catch (CertificationPathException certificationPathException) {
        // throw new
        // SignerCertificationPathException(SignerCertificationPathException.PROBLEM_WHEN_BUILDING_THE_CERTPATH,
        // certificationPathException);
        // }
    }

    /**
     * Define o certificado do signatário
     * @throws SignerCertificationPathException Exceção em caso de erro durante a busca pelo certificado
     */
    protected void setSignerCert() throws SignerCertificationPathException {
        SigningCertificateInterface signingCertificate = null;

        List<String> attributes = this.signature.getAttributeList();
        
        try {        
   
        	if (attributes.contains(IdAaSigningCertificate.IDENTIFIER))
                signingCertificate = new IdAaSigningCertificate(this, 0);
        	else if(attributes.contains(IdAaSigningCertificateV2.IDENTIFIER))
                signingCertificate = new IdAaSigningCertificateV2(this, 0);
   
        } catch (SignatureAttributeException signatureAttributeException) {
        	
       		throw new SignerCertificationPathException(SignerCertificationPathException.PROBLEM_TO_OBTAIN_SIGNINGCERTIFICATE, signatureAttributeException);
        }
        
        if(signingCertificate == null)
        	throw new SignerCertificationPathException(SignerCertificationPathException.PROBLEM_TO_OBTAIN_SIGNINGCERTIFICATE);
        
        List<CertificateCollection> certsCollection = this.component.certificateCollection;
        if (certsCollection == null) {
            certsCollection = new ArrayList<>();
            certsCollection.add(component.getSignatureIdentityInformation());
        }
        Certificate certTemp = null;
        int i = 0;
        
        while(certTemp == null && i < certsCollection.size()) { 
        	certTemp = certsCollection.get(i).getCertificate(signingCertificate); 
        	i++; 
        }

        if (certTemp != null) {
            this.signerCert = (X509Certificate) certTemp;
        }
    }

 
    /**
     * Retorna a assinatura que foi passada na construção da classe.
     * @return A assinatura CAdES
     */
    public CadesSignature getSignature() {
        return this.signature;
    }

    /**
     * Retorna o tempo em que o carimbo do tempo foi criado pela ACT ou caso o
     * carimbo do tempo não existir no conjunto de atributos usados na
     * assinatura, então retorna o tempo atual.
     * @return Horário em que o camrimbo do tempo foi criado pela ACT
     */
    public Time getTimeReference() {
        return this.timeReference;
    }

    /**
     * Atribui uma refêrencia de tempo que será utilizada no algoritmo de
     * validação dos caminho de certificação caso uma assinatura RT esteja válida.
     * @param timeReference Tempo que será usado como referência para a
     *            validação do caminho de certificação
     */
    public void setTemporaryTimeReference(Time timeReference) {
        this.temporaryTimeReference = timeReference;
    }
    
    /**
     * Retorna o tempo em que o carimbo do tempo foi criado pela ACT ou caso o
     * carimbo do tempo não existir no conjunto de atributos usados na
     * assinatura, então retorna o tempo atual.
     * @return O horário em que o camrimbo do tempo foi criado pela ACT
     */
    public Time getTemporaryTimeReference() {
        return this.temporaryTimeReference;
    }

    /**
     * Atribui uma refêrencia de tempo que será utilizada no algoritmo de
     * validação dos caminhos de certificação
     * @param timeReference O horário que será usado como referência para a
     *            validação do caminho de certificação
     */
    public void setTimeReference(Time timeReference) {
        this.timeReference = timeReference;
    }

//    /**
//     * Retorna o caminho de certificação do assinante.
//     * @return {@link CertPath}
//     */
    // public CertPath getSignerCertPath()
    // {
    // return this.certPath;
    // }

    /**
     * Retorna uma lista de respostas OCSP conhecida pelo verificador
     * @return A lista de respostas OCSP
     */
    public List<OCSPResp> getOcspList() {
        return ocspRespList;
    }

    /**
     * Retorna o certificado do servidor OCSP
     * @return O certificado do servidor OCSP
     */
    public X509Certificate getOcspServerCertificate() {
        return ocspServerCertificate;
    }

    /**
     * Informa a lista de OCSPs que devem ser usadas pelo verificador
     * @param ocsps A lista de respostas OCSP
     */
    public void setOcsps(List<OCSPResp> ocsps) {
        this.ocspRespList = ocsps;
    }

    /**
     * Define o certificado do servidor OCSP
     * @param ocspServerCertificate O certificado do servidor
     */
    public void setOcspServerCertificate(X509Certificate ocspServerCertificate) {
        this.ocspServerCertificate = ocspServerCertificate;
    }

    /**
     * Retorna a lista de prioridades dos carimbos do tempo
     * @return A lista de prioridades dos carimbos
     */
    public List<String> getTimeStampPriorityList() {
        return this.params.getTimeStampPriorityList();
    }

    /**
     * Retorna os paramêtros passados para esse verificador
     * @return Os parâmetros do verificador
     */
    public SignatureVerifierParams getParams() {
        return this.params;
    }

	/**
	 * Retorna o componente de assinaturas CAdES
	 * @return O componente de assinaturas CAdES
	 */
	public CadesSignatureComponent getCadesSignatureComponent() {
        return this.component;
    }

    /**
     * Verifica apenas os atributos obrigatórios e valida a assinatura.
     * Independente do resultado desse método, o método
     * getSignatureValidationErrors deve ser chamado.
	 * @param report O relatório de verificação da assinatura
     * @return Indica se a assinatura é válida
     * @throws PbadException Exceção em caso de erro durante a validação
     * @throws VerificationException Exceção em caso de erro durante a validação
     */
    public abstract boolean verify(SignatureReport report) throws PbadException, VerificationException;

    /**
     * Obtém a política de assinatura que define a verificação desse verificador
     * @return A política de assinatura
     */
    public abstract SignaturePolicyInterface getSignaturePolicy();

	/**
	 * Retorna o caminho de certificação
	 * @return O caminho de certificação
	 */
	public CertPath getCertPath() {
        return this.certPath;
    }

	/**
	 * Retorna o certificado do assinante
	 * @return O certificado do assinante
	 */
	public X509Certificate getSignerCert() {
		if (this.signerCert == null) {
			try {
				this.setSignerCert();
			} catch (SignerCertificationPathException e) {
				Application.logger.log(Level.WARNING, "Não foi possível obter o certificado do assinante", e);
			}
		}
        return this.signerCert;
    }

	/**
	 * Informa se a assinatura a ser verificada é um carimbo de tempo
	 * @return Indica se a assinatura a ser verificada é um carimbo
	 */
	public boolean isTimeStamp(){
        return this.isTimeStamp;
    }

	public void setComponent(CadesSignatureComponent component) {
		this.component = component;
	}
}
