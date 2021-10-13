package br.ufsc.labsec.signature.conformanceVerifier.xades;

/*

 Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
 da Universidade Federal de Santa Catarina (UFSC).

 Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
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

import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.ocsp.OCSPResp;

import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.AttributeMap;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureVerifierException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignerCertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.UnknowAttributeException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe trata as partes de verificação comuns entre assinaturas XAdES e
 * carimbos do tempo.
 */
public abstract class AbstractVerifier {

    /**
     * Assinatura a ser verificada.
     */
    protected XadesSignature signature;
    /**
     * Repositório de certificados que serão usados na validação
     */
    protected CertStore certStore;
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
     * Componente de assinatura XAdES
     */
    protected XadesSignatureComponent component;

    /**
     * Inicializa o Verifier de acodo com os parâmetros
     * @param signature A assinatura a ser verificada
     * @param params Os parâmetros de verificação
     * @throws SignatureVerifierException Exceção caso a assinatura seja nula
     */
    public void initialize(XadesSignature signature, SignatureVerifierParams params) throws SignatureVerifierException {
        if (params == null) {
            this.params = new SignatureVerifierParams();
        } else {
            this.params = params;
        }
        if (signature == null) {
            throw new SignatureVerifierException(SignatureVerifierException.SIGNATURE_NULL);
        }

        this.signature = signature;

        // TODO - Adicionar buscas no SignaturePoxy por atributos obrigatórios e
        // no CertificateCollection/RevocationInformation para montar um
        // certStore
    }

    /**
     * Os atributos da assinatura que tem o seu identificador presente na lista
     * de atributos obrigatórios passados aqui serão verificados.
     * <p>
     * 
     * Na lista <code>errors</code> serão retornados os erros que comprometem a
     * assinatura, já na lista de <code>warnings</code> seram retornados os
     * erros que aconteceram mas não infuenciam na validade da assinatura.
     * <p>
     * 
     * Os atributos que tem seu identificador presente na lista
     * attributesToExclude não serão verificados mesmo que presentes na lista de
     * atributos obrigatórios
     * 
     * @param warnings será atualizada com a lista de erros, que poderão
     *            ocorrer ao validar a assinatura, mas que não a tornam inválida
     * @param exceptions2 será atualizada com a lista de erros que tornam a
     *            assinatura inválida
     * @param signatureAttributeList lista de atributos presentes na
     *            assinatura que devem ser levados em conta
     * @param mandatedAttributeList lista de atributos que devem ser
     *            considerados obrigatórios
     * @param attributesToExclude lista de atributos que devem ser
     *            desconsiderados
     * @param sigReport o relatório de verificação
     */
    protected void verifyAttributesInMandatedList(List<PbadException> warnings, List<PbadException> exceptions2,
            List<String> signatureAttributeList, List<String> mandatedAttributeList, List<String> attributesToExclude,
            SignatureReport sigReport) {
        Map<String, Integer> identifierToCounter = new HashMap<String, Integer>();
        Map<String, List<PbadException>> identifierToErrors = new HashMap<String, List<PbadException>>();
        for (String attributeId : signatureAttributeList) {
            if (mandatedAttributeList.contains(attributeId)) {
                if (!attributesToExclude.contains(attributeId)) {
                    validateAttribute(identifierToCounter, identifierToErrors, attributeId, sigReport);
                } else {
                    for (AttribReport r: sigReport.getRequiredAttrib()) {
                        if (attributeId.equals(r.getAttribName())) {
                            if (r.getErrorMessage() != null) {
                                exceptions2.add(new PbadException(r.getErrorMessage()));
                            }
                            if (r.getWarningMessage() != null) {
                                warnings.add(new PbadException(r.getWarningMessage()));
                            }
                        }
                    }
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
     * Valida um atributo. Para fazer a validação o método busca a classe do atributo, e se a mesma
     * existir, ela será instanciada e seu método de validação chamado. Após a
     * execução do método o contador do atributo em questão e a sua lista de
     * erros serão atualizados.
     * 
     * @param identifierToCounter mapa entre identificador de atributo com a
     *            quantidade de aparições desse atributo
     * @param identifierToErrors mapa da lista de erros, que será atualizada
     *            após verificar o atributo
     * @param attributeId identificador do atributo
     * @param sigReport o relatório de verificação
     */
    private void validateAttribute(Map<String, Integer> identifierToCounter, Map<String, List<PbadException>> identifierToErrors,
            String attributeId, SignatureReport sigReport) {
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
        this.instantiateAndCallValidate(identifierToCounter, attributeId, attributeClass, attributeErrors, sigReport);
    }

    /**
     * Instancia e chama a validação da classe passada para o identificador
     * 
     * @param identifierToCounter mapa de contadores de atributos verificados
     *            que será atualizada após a execução desse método
     * @param attributeId identificador do atributo
     * @param attributeClass objeto que representa a classe do atributo que
     *            será verificado
     * @param attributeErrors lista de erros de validação do atributo que será
     *            atualizada após a execução desse método
     * @param sigReport o relatório de verificação
     */
    private void instantiateAndCallValidate(Map<String, Integer> identifierToCounter, String attributeId, Class<?> attributeClass,
            List<PbadException> attributeErrors, SignatureReport sigReport) {
        boolean error = false;
        if (attributeClass == null) {
            attributeErrors.add(new UnknowAttributeException(UnknowAttributeException.UNKNOW_ATTRIBUTE, attributeId));
            error = true;
        } else {
            Constructor<?> constructor = null;
            try {
                constructor = attributeClass.getConstructor(new Class<?>[] { AbstractVerifier.class, Integer.class });
            } catch (SecurityException securityException) {
                attributeErrors.add(new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId,
                        securityException.getStackTrace()));
                error = true;
            } catch (NoSuchMethodException noSuchMethodException) {
                attributeErrors.add(new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId,
                        noSuchMethodException.getStackTrace()));
                error = true;
            }
            SignatureAttribute attributeInstance = null;
            try {
                attributeInstance = (SignatureAttribute) constructor.newInstance(this, identifierToCounter.get(attributeId));
                if (!attributeId.equals("DataObjectFormat") && !attributeId.equals(PKCSObjectIdentifiers.pkcs_9_at_messageDigest.getId())) {
                    try {
                        attributeInstance.validate();
                        AttribReport attributeReport = new AttribReport();
                        attributeReport.setAttribName(attributeId);
                        attributeReport.setError(false);
                        sigReport.addAttribRequiredReport(attributeReport);
                    } catch (SignatureAttributeException signatureAttributeException) {
                        if (signatureAttributeException.getMessage().equals(SignatureAttributeException.INVALID_PA_OID)) {
                            attributeErrors.add(new SignatureAttributeException(signatureAttributeException.getMessage() + ": "
                                    + ((SignaturePolicyIdentifier)attributeInstance).getSignaturePolicyId()));
                            sigReport.setPaOidValid(false);
                        } else {
                            attributeErrors.add(signatureAttributeException);
                        }
                        error = true;
                    } catch (PbadException signatureException) {
                        attributeErrors.add(signatureException);
                        error = true;
                    } catch (NullPointerException nullPointerException) {
                        attributeErrors.add(new PbadException(nullPointerException));
                        error = true;
                    }
                }
                int counter = identifierToCounter.get(attributeId);
                counter++;
                identifierToCounter.put(attributeId, counter);
            } catch (IllegalArgumentException illegalArgumentException) {
                attributeErrors.add(new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId,
                        illegalArgumentException.getStackTrace()));
                error = true;
            } catch (InstantiationException instantiationException) {
                attributeErrors.add(new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId,
                        instantiationException.getStackTrace()));
                error = true;
            } catch (IllegalAccessException illegalAccessException) {
                attributeErrors.add(new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId,
                        illegalAccessException.getStackTrace()));
                error = true;
            } catch (InvocationTargetException invocationTargetException) {
                attributeErrors.add(new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId,
                        invocationTargetException.getStackTrace()));
                error = true;
            }
        }

        if (error) {
            AttribReport attributeReport = new AttribReport();
            attributeReport.setAttribName(attributeId);
            attributeReport.setError(true);
            attributeReport.setErrorMessage(attributeErrors.get(attributeErrors.size() - 1).getMessage());
            sigReport.addAttribRequiredReport(attributeReport);
        }
    }

    /**
     * Verifica apenas os atributos que não são obrigatórios segundo a lista
     * passada. A lista de atributos que não devem ser verificados mesmo que não
     * sejam obrigatórios será levada em conta.
     * 
     * @param signatureAttributeList lista de atributos da assinatura
     * @param mandatedAttributeList lista de atributo obrigatórios, de acordo
     *            com a política de assinatura
     * @param attributesToExclude atributos a serem ignorados
     * 
     * @return Lista que contém os erros de validação. Será vazia se não ocorrer erros
     */
    protected List<PbadException> verifyOnlyUnmandatedAttributes(List<String> signatureAttributeList, List<String> mandatedAttributeList,
            List<String> attributesToExclude, SignatureReport sigReport) {
        List<PbadException> errors = new ArrayList<PbadException>();
        boolean error;
        Class<?> attributeClass = null;
        Constructor<?> constructor = null;
        Map<String, Integer> identifierToCounter = new HashMap<String, Integer>();
        for (String attributeId : signatureAttributeList) {
            error = false;
            if (!mandatedAttributeList.contains(attributeId)) {
                if (!attributesToExclude.contains(attributeId)) {
                    if (!identifierToCounter.containsKey(attributeId)) {
                        identifierToCounter.put(attributeId, 0);
                    }
                    attributeClass = AttributeMap.getAttributeClass(attributeId);
                    /*
                     * Se é um atributo desconhecido que é obrigatório e este
                     * não pode se validado, ele invalidará a assinatura.
                     */
                    if (attributeClass == null) {
                        errors.add(new UnknowAttributeException(UnknowAttributeException.UNKNOW_ATTRIBUTE, attributeId));
                        error = true;
                    } else {
                        try {
                            constructor = attributeClass.getConstructor(new Class<?>[] { AbstractVerifier.class, Integer.class });
                        } catch (SecurityException securityException) {
                            errors.add(new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId,
                                    securityException.getStackTrace()));
                            error = true;
                        } catch (NoSuchMethodException noSuchMethodException) {
                            errors.add(new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId,
                                    noSuchMethodException.getStackTrace()));
                            error = true;
                        }
                        SignatureAttribute attributeInstance = null;
                        try {
                            attributeInstance = (SignatureAttribute) constructor.newInstance(this, identifierToCounter.get(attributeId));
                            if (!attributeId.equals("DataObjectFormat") && !attributeId.equals(PKCSObjectIdentifiers.pkcs_9_at_messageDigest.getId())) {
                                try {
                                    attributeInstance.validate();
                                    AttribReport attribReport = new AttribReport();
                                    attribReport.setAttribName(attributeId);
                                    attribReport.setError(false);
                                    sigReport.addAttribOptionalReport(attribReport);
                                    
                                } catch (SignatureAttributeException signatureAttributeException) {
                                    if (signatureAttributeException.getMessage().equals(SignatureAttributeException.INVALID_PA_OID)) {
                                        errors.add(new SignatureAttributeException(signatureAttributeException.getMessage()
                                                + ((SignaturePolicyIdentifier)attributeInstance).getSignaturePolicyId()));
                                        sigReport.setPaOidValid(false);
                                    } else {
                                        errors.add(signatureAttributeException);
                                    }
                                    error = true;
                                } catch (PbadException signatureException) {
                                    errors.add(signatureException);
                                    error = true;
                                }
                            }
                            int counter = identifierToCounter.get(attributeId);
                            counter++;
                            identifierToCounter.put(attributeId, counter);
                        } catch (IllegalArgumentException illegalArgumentException) {
                            errors.add(new SignatureAttributeException(
                                    SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId, illegalArgumentException
                                            .getStackTrace()));
                            error = true;
                        } catch (InstantiationException instantiationException) {
                            errors.add(new SignatureAttributeException(
                                    SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId, instantiationException
                                            .getStackTrace()));
                            error = true;
                        } catch (IllegalAccessException illegalAccessException) {
                            errors.add(new SignatureAttributeException(
                                    SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId, illegalAccessException
                                            .getStackTrace()));
                            error = true;
                        } catch (InvocationTargetException invocationTargetException) {
                            errors.add(new SignatureAttributeException(
                                    SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + attributeId, invocationTargetException
                                            .getStackTrace()));
                            error = true;
                        }
                    }
                }
            }
            
            if (error) {
                    AttribReport attribReport = new AttribReport();
                    attribReport.setAttribName(attributeId);
                    attribReport.setError(true);
                    attribReport.setErrorMessage(errors.get(errors.size() - 1).getMessage());
                    sigReport.addAttribOptionalReport(attribReport);
            }
            
        }
        
        return errors;
    }

    /**
     * Executa o algoritmo responsável pela verificação das políticas de
     * certificação aceitáveis
     * 
     * @param trustPoint certificado da âncora de confiança
     * 
     * @throws CertificationPathException exceção em caso de erro no caminho de certificação
     */
    protected void checkAcceptablePolicies(CertificateTrustPoint trustPoint) throws CertificationPathException {
        if (trustPoint.getAcceptablePolicySet() != null) {
            TrustAnchor trustAnchor = new TrustAnchor((X509Certificate) trustPoint.getTrustPoint(), null);
            // FIXME - Isso será substituido por uma Chamada para a interface
            // CertificateValidation ou alguma coisa parecida
            // no componente de validação de caminho de certificação
            // CertPathValidator.validateCertPathPolicies(this.certPath,
            // trustPoint.getAcceptablePolicySet(), trustAnchor);
        }
    }

    /**
     * Define o certificado do signatário
     * 
     * @throws SignerCertificationPathException exceção em caso de erro ao obter o certificado do assinante
     */
    protected void setSignerCert() throws SignerCertificationPathException {
        SigningCertificate signingCertificate = null;

        List<String> attributes = this.signature.getAttributeList();
        if (attributes.contains(SigningCertificate.IDENTIFIER)) {
            try {
                signingCertificate = new SigningCertificate(this, 0);
            } catch (SignatureAttributeException signatureAttributeException) {
                throw new SignerCertificationPathException(SignerCertificationPathException.PROBLEM_TO_OBTAIN_SIGNINGCERTIFICATE,
                        signatureAttributeException);
            }
        }

        List<CertificateCollection> certsCollection = this.component.certificateCollection; 


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
     * Retorna o repositório de certificados conhecido pelo verificador
     * 
     * @return {@link CertStore} repositório de certificados conhecido pelo
     *         verificador
     */
    public CertStore getCertStore() {
        return this.certStore;
    }

    /**
     * Retorna a assinatura que foi passada na construção da classe
     * 
     * @return a assinatura que é verificada
     */
    public XadesSignature getSignature() {
        return this.signature;
    }

    /**
     * Retorna o tempo em que o carimbo do tempo foi criado pela ACT ou, caso o
     * carimbo do tempo não existir no conjunto de atributos usados na
     * assinatura, então retorna o tempo atual.
     * 
     * @return {@link Time} tempo em que o camrimbo do tempo foi criado pela ACT
     */
    public Time getTimeReference() {
        return this.timeReference;
    }
    

    /**
     * Atribue uma refêrencia de tempo que será utilizada no algoritmo de
     * validação dos caminhos de certificação
     * 
     * @param timeReference tempo que será usado como referência para a
     *            validação do caminho de certificação
     */
    public void setTimeReference(Time timeReference) {
        this.timeReference = timeReference;
    }
    
    /**
     * Atribue uma refêrencia de tempo que será utilizada no algoritmo de
     * validação dos caminho de certificação caso uma assinatura RT esteja valida.
     * 
     * @param timeReference tempo que será usado como referência para a
     *            validação do caminho de certificação
     */
    public void setTemporaryTimeReference(Time timeReference) {
        this.temporaryTimeReference = timeReference;
    }

    /**
     * Retorna o caminho de certificação do assinante
     * 
     * @return o caminho de certificação do assinante
     */
    public CertPath getSignerCertPath() {
        return this.certPath;
    }

    /**
     * Retorna uma lista de respostas OCSP conhecida pelo verificador
     * 
     * @return lista de respostas OCSP
     */
    public List<OCSPResp> getOcspList() {
        return ocspRespList;
    }

    /**
     * Obtém certificado do servidor OCSP
     * 
     * @return o certificado do servidor OCSP
     */
    public X509Certificate getOcspServerCertificate() {
        return ocspServerCertificate;
    }

    /**
     * Atribue um repositório de certificados
     * @param certStore o repositório de certificados
     */
    public void setCertStore(CertStore certStore) {
        this.certStore = certStore;
    }

    /**
     * Informa a lista de OCSPs que devem ser usadas pelo verificador
     * 
     * @param ocsps a lista de OCSPs que devem ser utilizadas
     */
    public void setOcsps(List<OCSPResp> ocsps) {
        this.ocspRespList = ocsps;
    }

    /**
     * Define o certificado do servidor OCSP
     * 
     * @param ocspServerCertificate o certificado do servidor OCSP
     */
    public void setOcspServerCertificate(X509Certificate ocspServerCertificate) {
        this.ocspServerCertificate = ocspServerCertificate;
    }

    /**
     * Retorna a lista de prioridades dos carimbos do tempo
     * 
     * @return a lista de prioridades dos carimbos do tempo
     */
    public List<String> getTimeStampPriorityList() {
        return this.params.getTimeStampPriorityList();
    }
    
    /**
     * Retorna o tempo em que o carimbo do tempo foi criado pela ACT ou caso o
     * carimbo do tempo não existir no conjunto de atributos usados na
     * assinatura, então retorna o tempo atual.
     * 
     * @return {@link Time} tempo em que o camrimbo do tempo foi criado pela ACT
     */
    public Time getTemporaryTimeReference() {
        return this.temporaryTimeReference;
    }

    /**
     * Retorna os paramêtros passados para esse verificador
     * 
     * @return os paramêtros de inicialização
     */
    public SignatureVerifierParams getParams() {
        return this.params;
    }

    /**
     * Retorna o componente de assinatura XAdES
     * @return o componente de assinatura XAdES
     */
    public XadesSignatureComponent getXadesSignatureComponent() {
        return this.component;
    }

    /**
     * Retorna o certificado do assinante
     * @return o certificado do assinante
     */
    public X509Certificate getSignerCertificate() {
        return this.signerCert;
    }

    /**
     * Verifica apenas os atributos obrigatórios e valida a assinatura.
     * <p>
     * 
     * Independente do resultado desse método, o método
     * getSignatureValidationErrors deve ser chamado.
     *
     * @param sigReport o relatório de verificação de uma assinatura
     * @return indica se a assinatura é válida
     * 
     */
    public abstract boolean verify(SignatureReport sigReport);

    /**
     * Retorna a política de assinatura utilizada na assinatura
     * @return a política de assinatura utilizada
     */
    public abstract SignaturePolicyInterface getSignaturePolicy();
}
