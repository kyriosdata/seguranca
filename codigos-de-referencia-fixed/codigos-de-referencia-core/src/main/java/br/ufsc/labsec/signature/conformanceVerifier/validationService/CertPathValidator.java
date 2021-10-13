/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.sql.Time;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.ocsp.OCSPResp;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.ValidationDataReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertRevReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.RevReq;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.exceptions.CertificationPolicyException;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.exceptions.SignerCertificationPathException;
import br.ufsc.labsec.signature.exceptions.OcspException;

/**
 * Esta classe é responsável pela validação do caminho de
 * certificação de um certificado
 */
public class CertPathValidator {

    private static final String PKIX = "PKIX";

    /**
     * Valida o caminho de certificação de um certificado. Caso seja feita
     * verificação por OCSP então os parâmetros ocspRespList e
     * ocspServerCertificate NÃO PODEM ser nulos. Se for apenas por CRLs, então
     * tais parâmetros DEVEM ser nulos
     * 
     * @param certificate Certificado final do caminho de certificação
     * @param certStore Objeto que contêm os certificados e as LCRs para a
     *            construção do caminho de certificação
     * @param timeReference Data para validação
     * @param trustAnchors Possíveis âncoras de confiança para o caminho de
     *            certificação
     * @param revocationRequirements Requisitos para verificação do status de
     *            revogação dos certificados
     * @param ocspRespList Lista de respostas OCSP
     * @param ocspServerCertificate Certificado do servidor OCSP
     * @param sigReport O relatório da assintura
     * @param certificateValidationService Serviço de validação de certificados
     * 
     * @throws CertificationPathException Exceção no caminho do certificado
     * @throws OcspException Exceção na verificação por OCSP
     * @throws SignerCertificationPathException Exceção no caminho de certificação do certificado do assinante
     */
    public static void validateCertPath(X509Certificate certificate, CertStore certStore, Time timeReference,
            Set<TrustAnchor> trustAnchors, CertRevReq revocationRequirements, List<OCSPResp> ocspRespList,
            X509Certificate ocspServerCertificate, SignatureReport sigReport, CertificateValidationService certificateValidationService) throws CertificationPathException, OcspException, SignerCertificationPathException {

        // Apenas os certificados de AC raiz são passados como âncoras de confiança
        // para a construção do caminho de certificação
        Set<TrustAnchor> trustAnchorsRoots = new HashSet<>();
        X509Certificate taCert;
        for (TrustAnchor ta : trustAnchors) {
            taCert = ta.getTrustedCert();
            if (taCert.getSubjectX500Principal().equals(taCert.getIssuerX500Principal())){
                trustAnchorsRoots.add(ta);
            }
        }

        CertPath certPath;
        try{
            certPath = CertPathBuilder.buildPath(certificate, certStore, trustAnchorsRoots, timeReference, false);
        } catch (CertificationPathException exception) {
            addLcrValidation(certStore, sigReport, certificateValidationService);
            throw exception;
        }

        buildValidationDataReport(trustAnchors, sigReport, certPath);

        addLcrValidation(certStore, sigReport, certificateValidationService);

        CertPathValidator.validateCertPath(certPath, certStore, timeReference, trustAnchorsRoots, revocationRequirements, ocspRespList,
                ocspServerCertificate);

        
    }

    /**
     * Adiciona os relatórios de validação dos certificados ao relatório da assinatura
     * @param trustAnchors Âncoras de confiança do caminho de certificação
     * @param sigReport O relatório da assintura
     * @param certPath Caminho de certificação
     */
	public static void buildValidationDataReport(Set<TrustAnchor> trustAnchors, SignatureReport sigReport,
			CertPath certPath) {
		for (int i = 0; i < certPath.getCertificates().size() - 1; i++) {
            X509Certificate subjectCert = (X509Certificate) certPath.getCertificates().get(i);
            X509Certificate issuerCert = (X509Certificate) certPath.getCertificates().get(i + 1);

            sigReport.addValidation(getValidationData(subjectCert, issuerCert));

        }

        X509Certificate subjectCert = (X509Certificate) certPath.getCertificates().get(certPath.getCertificates().size() - 1);

        TrustAnchor selectedTrustAnchor = null;

        for (TrustAnchor trustAnchor : trustAnchors) {

            if (trustAnchor.getTrustedCert().getSubjectX500Principal().equals(subjectCert.getIssuerX500Principal()))
                selectedTrustAnchor = trustAnchor;
        }

        sigReport.addValidation(getValidationData(subjectCert, selectedTrustAnchor.getTrustedCert()));
        sigReport.addValidation(getValidationData(selectedTrustAnchor.getTrustedCert(), selectedTrustAnchor.getTrustedCert()));
	}

    /**
     * Adiciona itens da validação da LCR no relatório
     * @param certStore Objeto que contêm os certificados e as LCRs para a
     *  construção do caminho de certificação
     * @param sigReport O relatório da assintura
     * @param certificateValidationService Serviço de validação de certificados
     */
    private static void addLcrValidation(CertStore certStore, SignatureReport sigReport, CertificateValidationService certificateValidationService) {

        Collection<? extends CRL> crls = Collections.EMPTY_LIST;
        try {
            crls = certStore.getCRLs(new X509CRLSelector());
        } catch (CertStoreException e) {
            Application.logger.log(Level.SEVERE, "Erro no acesso à lista de LCRs do CertStore", e);
        }

        for (CRL value : crls) {
            X509CRL crl = (X509CRL) value;
            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setSubject(crl.getIssuerX500Principal());

            Collection<? extends Certificate> certList = null;
            try {
                certList = certStore.getCertificates(certSelector);
            } catch (CertStoreException e) {
                Application.logger.log(Level.SEVERE, "Erro no acesso à lista de certificados do CertStore", e);
                return;
            } finally {
                Iterator<? extends Certificate> certIterator = certList.iterator();
                if (certIterator.hasNext()) {
                    sigReport.addValidation(getCrlValidationData(crl, (X509Certificate) certIterator.next(), certificateValidationService));
                }
            }
        }

    }

    /**
     * Gera um relatório da validação com as informações dos certificados e LCRs
     * @param crl LCR a ser verificada
     * @param issuerCert Certificado do emissor
     * @param certificateValidationService Serviço de validação de certificados
     * @return O relatório com as informações das validações dos certificados e LCRs
     */
    private static ValidationDataReport getCrlValidationData(X509CRL crl, X509Certificate issuerCert, CertificateValidationService certificateValidationService) {
        ValidationDataReport validationData = new ValidationDataReport();

        boolean valid = true;

        try {
            crl.verify(issuerCert.getPublicKey());
        } catch (Exception e) {
            valid = false;
        }

        validationData.setValidCrl(valid);

        validationData.setCrlIssuerName(crl.getIssuerX500Principal().toString());

        DEROctetString derOctectString = null;
        try {
            derOctectString = ((DEROctetString) ASN1Sequence.fromByteArray(crl.getExtensionValue("2.5.29.20")));
        } catch (IOException e1) {
            Application.logger.log(Level.SEVERE, "Erro no acesso ao DER Octetc String", e1);
        }

        ASN1Integer crlNumber = null;
        try {
            crlNumber = (ASN1Integer) ASN1Sequence.fromByteArray(derOctectString.getOctets());
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, "Erro no acesso ao crl number", e);
        }

        validationData.setCrlOnline(certificateValidationService.isCrlFromWeb(crl));
        validationData.setCrlSerialNumber(crlNumber.getValue().toString());
        
        validationData.setNextUpdate(crl.getNextUpdate());
        validationData.setThisUpdate(crl.getThisUpdate());

        return validationData;

    }

    /**
     * Gera um relatório da validação dos certificados dados
     * @param subjectCert Certificado do assinante
     * @param issuerCert Certificado do emissor
     * @return Relatório da validação dos certificados
     */
    public static ValidationDataReport getValidationData(X509Certificate subjectCert, X509Certificate issuerCert) {
        ValidationDataReport validationData = new ValidationDataReport();

        validationData.setCertificateOnline(false);
        boolean valid = true;

        try {
            subjectCert.verify(issuerCert.getPublicKey());
        } catch (Exception e) {
            valid = false;
        }

        validationData.setValidCertificate(valid);

        validationData.setCertificateIssuerName(subjectCert.getIssuerX500Principal().toString());

		validationData.setNotBefore(subjectCert.getNotBefore());
		
		validationData.setNotAfter(subjectCert.getNotAfter());

        validationData.setCertificateSubjectName(subjectCert.getSubjectX500Principal().toString());

        validationData.setCertificateSerialNumber(subjectCert.getSerialNumber().toString());

        return validationData;
    }

    /**
     * Valida o caminho de certificação de um certificado
     * 
     * @param certPath Caminho de certificação a ser validado
     * @param certStore Objeto que contêm os certificados e as LCRs para a
     *            construção do caminho de certificação
     * @param timeReference Data para validação
     * @param trustAnchors Possíveis âncoras de confiança para o caminho de
     *            certificação
     * @param revocationRequirements Requisitos para verificação do status de
     *            revogação dos certificados
     * @param ocspRespList Lista de respostas OCSP
     * @param ocspServerCertificate Certificado do servidor OCSP
     * 
     * @throws CertificationPathException Exceção em caso de erro ao validar o caminho
     *             de certificação
     * @throws OcspException Exceção em caso de erro com o OCSP
     * @throws SignerCertificationPathException  Exceção no caminho de certificação do certificado do assinante
     */
    public static void validateCertPath(CertPath certPath, CertStore certStore, Time timeReference, Set<TrustAnchor> trustAnchors,
            CertRevReq revocationRequirements, List<OCSPResp> ocspRespList, X509Certificate ocspServerCertificate)
        throws CertificationPathException, OcspException, SignerCertificationPathException {

        if (certPath == null) {
            throw new CertificationPathException(CertificationPathException.NULL_CERT_PATH);
        }

        RevReq caRevReq = revocationRequirements.getCaCerts();
        RevReq endRevReq = revocationRequirements.getEndCertRevReq();

        /*
         * Se a verificação pode ser por qualquer um dos métodos da-se
         * preferencia pela revogação por CRL
         */
        boolean caValidationIsEitherCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.EITHER_CHECK;
        boolean caValidationIsCrlCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.CLR_CHECK;
        boolean endValidationIsEitherCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.EITHER_CHECK;
        boolean endValidationIsCrlCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.CLR_CHECK;
        boolean endValidationIsOtherCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.OTHER;
        boolean caValidationIsOtherCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.OTHER;
        boolean caValidationCanBeCrl = caValidationIsEitherCheck || caValidationIsCrlCheck;
        boolean endValidationCanBeCrl = endValidationIsEitherCheck || endValidationIsCrlCheck;
        boolean caValidationIsOcspCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.OCSP_CHECK;
        boolean endValidationIsOcspCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.OCSP_CHECK;
        boolean allValidationMustBeOcsp = caValidationIsOcspCheck && endValidationIsOcspCheck;

        if (caValidationCanBeCrl && endValidationCanBeCrl) {
            CertPathValidator.validateWithCrls(certPath, certStore, timeReference, trustAnchors);
        }
        /* Se a verificação de todos os certificados deve ser via OCSP */
        if (allValidationMustBeOcsp) {
            CertPathValidator.validateWithOcsp(certPath, certStore, timeReference, trustAnchors, ocspRespList, ocspServerCertificate);
        }
        /*
         * Se apenas o certificado do assinante deve ser verificado via OCSP e
         * as ACs via LCRs ou qualquer
         */
        if (endValidationIsOcspCheck && (caValidationIsCrlCheck || caValidationIsEitherCheck)) {
            CertPathValidator.validateEndCertWithOcspAndCasWithCrls(certPath, certStore, timeReference, trustAnchors, ocspRespList,
                    ocspServerCertificate);
        }
        /*
         * Se apenas o certificado do assinante deve ser verificado via LCR ou
         * qualquer e os das ACs deve ser verificado via OCSP
         */
        if ((endValidationIsCrlCheck || endValidationIsEitherCheck) && caValidationIsOcspCheck) {
            CertPathValidator.validateEndCertWithCrlAndCasWithOcsp(certPath, certStore, timeReference, trustAnchors, ocspRespList,
                    ocspServerCertificate);
        }
        /*
         * Se a verificação do certificado final ou dos certificados das ACs
         * devem ser feitas segundo outro método que não os citados acima
         */
        if (endValidationIsOtherCheck || caValidationIsOtherCheck) {
            throw new CertificationPathException(CertificationPathException.UNKNOWN_CERT_PATH_VALIDATION);
        }
    }

    /**
     * Valida o caminho de certificação de um certificado através de LCRs
     * (Lista de Certificados Revogados)
     *
     * @param certPath Caminho de certificação a ser validado
     * @param certStore Oobjeto que contêm os certificados e as LCRs do caminho
     *            de certificação
     * @param timeReference Data para validação
     * @param trustAnchors Possíveis âncoras de confiança para o caminho de
     *            certificação
     * @throws CertificationPathException Exceção no caminho de certificação
     */
    protected static void validateWithCrls(CertPath certPath, CertStore certStore, Time timeReference, Set<TrustAnchor> trustAnchors)
        throws CertificationPathException {
        // CertPath certPath = CertPathBuilder.builPath(certificate,
        // certStore, trustAnchors, false);
        java.security.cert.CertPathValidator certPathValidator = null;
        try {
            certPathValidator = java.security.cert.CertPathValidator.getInstance(PKIX);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new CertificationPathException(CertificationPathException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
        }
        PKIXParameters pkixParams = null;
        try {
            pkixParams = new PKIXParameters(trustAnchors);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
                    invalidAlgorithmParameterException);
        }
        pkixParams.addCertStore(certStore);
        pkixParams.setDate(timeReference);

        try {
            certPathValidator.validate(certPath, pkixParams);
        } catch (CertPathValidatorException certPathValidatorException) {
            throw new CertificationPathException(CertificationPathException.PROBLEM_TO_VALIDATE_CERTPATH, certPathValidatorException);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
                    invalidAlgorithmParameterException);
        }

    }

    /**
     * Valida o caminho de certificação de um certificado através de
     * servidor OCSP
     * 
     * @param certPath Caminho de certificação a ser validado
     * @param certStore Objeto que contêm os certificados do caminho de
     *            certificação
     * @param timeReference Data para validação
     * @param trustAnchors Possíveis âncoras de confiança para o caminho de
     *            certificação
     * @param ocspList Lista de respostas OCSP
     * @param ocspServerCertificate Certificado do servidor OCSP
     * 
     * @throws OcspException Erro na validação a uma resposta OCSP
     * @throws CertificationPathException Exceção no caminho de certificação
     */
    protected static void validateWithOcsp(CertPath certPath, CertStore certStore, Time timeReference, Set<TrustAnchor> trustAnchors,
            List<OCSPResp> ocspList, X509Certificate ocspServerCertificate) throws CertificationPathException, OcspException {
        PKIXParameters pkixParams;
        try {
            pkixParams = new PKIXParameters(trustAnchors);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
                    invalidAlgorithmParameterException);
        }
        pkixParams.addCertPathChecker(new OcspCertificateChecker(ocspList, ocspServerCertificate, timeReference));
        /* A revogação por CRLs está desligada */
        pkixParams.setRevocationEnabled(false);
        java.security.cert.CertPathValidator certValidator;
        try {
            certValidator = java.security.cert.CertPathValidator.getInstance(PKIX);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new CertificationPathException(CertificationPathException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
        }
        try {
            certValidator.validate(certPath, pkixParams);
        } catch (CertPathValidatorException certPathValidatorException) {
            throw new CertificationPathException(CertificationPathException.PROBLEM_TO_VALIDATE_CERTPATH, certPathValidatorException);
        } catch (InvalidAlgorithmParameterException certPathValidatorException) {
            throw new CertificationPathException(CertificationPathException.PROBLEM_TO_VALIDATE_CERTPATH, certPathValidatorException);
        }
    }

    /**
     * Valida o caminho de certificação do certificado final através de
     * servidor OCSP e os certificados de ACs através de LCRs
     * 
     * @param certPath Caminho de certificação a ser validado
     * @param certStore Objeto que contêm os certificados e LCRs do caminho de
     *            certificação
     * @param timeReference Data para validação
     * @param trustAnchors Possíveis âncoras de confiança para o caminho de
     *            certificação
     * @param ocspList Lista de respostas OCSP
     * @param ocspServerCertificate Certificado do servidor OCSP
     * 
     * @throws OcspException Erro na validação a uma resposta ocsp
     * @throws CertificationPathException Exceção no caminho de certificação
     */
    protected static void validateEndCertWithOcspAndCasWithCrls(CertPath certPath, CertStore certStore, Time timeReference,
            Set<TrustAnchor> trustAnchors, List<OCSPResp> ocspList, X509Certificate ocspServerCertificate) throws OcspException,
        CertificationPathException {

        OcspCertificateChecker checker;
        checker = new OcspCertificateChecker(ocspList, ocspServerCertificate, timeReference);
        /*
         * Os certificados vem em ordem. Portanto o primeiro é o certificado do
         * assinante.
         */
        checker.check(certPath.getCertificates().get(0), true);
        /*
         * É feita a construção do caminho com a validação habilitada para
         * validar a parte restante do caminho com LCRs
         */
        CertPathBuilder.buildPath((X509Certificate) certPath.getCertificates().get(1), certStore, trustAnchors, timeReference, true);
    }

    /**
     * Valida o caminho de certificação do certificado final através de LCRs
     * e os certificados de ACs através de servidor OCSP
     * 
     * @param certPath Caminho de certificação a ser validado
     * @param certStore Objeto que contêm os certificados e LCRs do caminho de
     *            certificação
     * @param timeReference Data para validação
     * @param trustAnchors Possíveis âncoras de confiança para o caminho de
     *            certificação
     * @param ocspList Lista de respostas OCSP
     * @param ocspServerCertificate Certificado do servidor OCSP
     * 
     * @throws OcspException Erro na validação a uma resposta ocsp
     * @throws CertificationPathException Exceção no caminho de certificação
     * @throws SignerCertificationPathException Exceção no caminho de certificação do certificado do assinante
     */
    @SuppressWarnings("unchecked")
    protected static void validateEndCertWithCrlAndCasWithOcsp(CertPath certPath, CertStore certStore, Time timeReference,
            Set<TrustAnchor> trustAnchors, List<OCSPResp> ocspList, X509Certificate ocspServerCertificate) throws OcspException,
        CertificationPathException, SignerCertificationPathException {
        X509Certificate endCert = (X509Certificate) certPath.getCertificates().get(0);
        X509CRLSelector crlSelector = new X509CRLSelector();
        crlSelector.addIssuer(endCert.getIssuerX500Principal());
        X509CRL crl = null;
        try {
            crl = (X509CRL) certStore.getCRLs(crlSelector).iterator().next();
        } catch (CertStoreException certStoreException) {
            throw new CertificationPathException(CertificationPathException.ERROR_WHEN_SELECTING_CRL_IN_THE_CERTSTORE, certStoreException);
        }
        X509CRLEntry entry = crl.getRevokedCertificate(endCert);
        if (entry != null && entry.getRevocationDate().before(timeReference)) {
            throw new SignerCertificationPathException(SignerCertificationPathException.INVALID_SIGNER_CERTIFICATE);
        }
        OcspCertificateChecker checker;
        checker = new OcspCertificateChecker(ocspList, ocspServerCertificate, timeReference);
        X509CertSelector selector = new X509CertSelector();
        /* Certificado da próxima AC vai ser usado como origem do caminho. */
        selector.setCertificate((X509Certificate) certPath.getCertificates().get(1));
        List<X509Extension> certsAndCrls = new ArrayList<X509Extension>((Collection<? extends X509Extension>) certPath.getCertificates());
        try {
            certsAndCrls.addAll((Collection<? extends X509Extension>) (certStore.getCRLs(null)));
        } catch (CertStoreException certStoreException) {
            throw new CertificationPathException(CertificationPathException.ERROR_WHEN_SELECTING_CRL_IN_THE_CERTSTORE, certStoreException);
        }
        CollectionCertStoreParameters certParams = new CollectionCertStoreParameters(certsAndCrls);
        CertStore store = null;
        try {
            store = CertStore.getInstance("Collection", certParams);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
                    invalidAlgorithmParameterException);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new CertificationPathException(CertificationPathException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
        }
        PKIXBuilderParameters params = null;
        try {
            params = new PKIXBuilderParameters(trustAnchors, selector);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
                    invalidAlgorithmParameterException);
        }
        params.addCertStore(store);
        params.addCertPathChecker(checker);
        params.setRevocationEnabled(false);
        java.security.cert.CertPathBuilder builder;
        try {
            builder = java.security.cert.CertPathBuilder.getInstance(PKIX);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new CertificationPathException(CertificationPathException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
        }
        try {
            builder.build(params);
        } catch (CertPathBuilderException certPathBuilderException) {
            throw new CertificationPathException(CertificationPathException.PROBLEM_TO_VALIDATE_CERTPATH, certPathBuilderException);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
                    invalidAlgorithmParameterException);
        }
    }

    /**
     * Valida as políticas de certificação de um cadeia de certificados
     * 
     * @param certPath Caminho de certificação
     * @param acceptablePolicySet Conjunto de políticas de certificação
     *            aceitáveis
     * @param trustPoint Possíveis âncoras de confiança para o caminho de
     *            certificação
     * 
     * @throws CertificationPathException Exceção caminho de certificação
     * @throws CertificationPolicyException Exceção na validação das políticas de certificação
     */
    public static void validateCertPathPolicies(CertPath certPath, String[] acceptablePolicySet, TrustAnchor trustPoint)
        throws CertificationPathException, CertificationPolicyException {
        Set<TrustAnchor> trustAnchors = Collections.singleton(trustPoint);
        PKIXParameters pkixParams;
        try {
            pkixParams = new PKIXParameters(trustAnchors);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
                    invalidAlgorithmParameterException);
        }
        pkixParams.setInitialPolicies(new HashSet<String>(Arrays.asList(acceptablePolicySet)));
        pkixParams.setRevocationEnabled(false);
        pkixParams.setExplicitPolicyRequired(true);

        java.security.cert.CertPathValidator certPathValidator = null;
        try {
            certPathValidator = java.security.cert.CertPathValidator.getInstance(PKIX);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new CertificationPathException(CertificationPathException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
        }
        try {
            certPathValidator.validate(certPath, pkixParams);
        } catch (CertPathValidatorException certPathValidatorException) {
            throw new CertificationPolicyException(CertificationPathException.PROBLEM_TO_VALIDATE_CERTPATH);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM);
        }
    }
}
