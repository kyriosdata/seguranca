/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import java.io.IOException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;

import br.ufsc.labsec.signature.exceptions.OcspException;


/**
 * Esta classe é usada para obter o status de revogação de um certificado
 * digital X.509, utilizando o método OCSP (Online Certificate Status Protocol).
 * 
 * @see <a href="http://tools.ietf.org/html/rfc2560">RFC 2560</a>
 */
public class OcspCertificateChecker extends PKIXCertPathChecker {

    /**
     * Mapa que relaciona o certificado com o seu status de revogação
     */
    private Map<CertificateID, CertificateStatus> certStatus;
    /**
     * Data da verificação
     */
    private Time currentDate;

    /**
     * Inicializa o verificador
     * 
     * @param ocsps Lista de respostas OCSPs
     * @param certificate Certificado do servidor OCSPs responsável pelas
     *            respostas
     * @param currentDate Data da verificação
     * @throws OcspException exceção em caso de erro na verificação
     */
    public OcspCertificateChecker(List<OCSPResp> ocsps, X509Certificate certificate, Time currentDate) throws OcspException {
        boolean removeProvider = false;
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            removeProvider = true;
        }
        this.certStatus = new HashMap<CertificateID, CertificateStatus>();
        this.currentDate = currentDate;
        if (ocsps != null && !ocsps.isEmpty()) {
            try {
                for (OCSPResp resp : ocsps) {
                    BasicOCSPResp basicResp = (BasicOCSPResp) resp.getResponseObject();
                    basicResp = (BasicOCSPResp) ocsps.get(0).getResponseObject();
                    PublicKey pubKey = certificate.getPublicKey();
                    ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().build(pubKey);
                    if (basicResp.isSignatureValid(verifierProvider)) {
                        SingleResp[] resps = basicResp.getResponses();
                        /* Achar o id do certificado procurado ... */
                        for (SingleResp singleResp : resps) {
                            this.certStatus.put(singleResp.getCertID(), (CertificateStatus) singleResp.getCertStatus());
                        }
                    }
                }
            } catch (Exception exception) {
                throw new OcspException(OcspException.ERROR_WHEN_PREPARING_VALIDATION_WITH_OCSP, exception);
            }
        } else {
            throw new OcspException(OcspException.WITHOUT_RESPONSE);
        }
        if (removeProvider)
            Security.removeProvider("BC");
    }

    /**
     * Busca por uma resposta OCSP para o certificado dado e vê se a resposta
     * de revogação é anterior à data atual.
     * 
     * @param certificate Certificado a ser verificado
     * @throws OcspException exceção em caso de erro na verificação
     */
    public void check(Certificate certificate, boolean isJava8) throws OcspException {
        boolean removeProvider = false;
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            removeProvider = true;
        }
        
        CertificateID certID = null;
        try {
        	X509CertificateHolder cert = new X509CertificateHolder(certificate.getEncoded());
            certID = new CertificateID((DigestCalculator) CertificateID.HASH_SHA1, cert, cert.getSerialNumber());
        } catch (OCSPException | CertificateEncodingException | IOException e) {
            throw new OcspException(e);
        }
        if (!this.certStatus.containsKey(certID)) {
            throw new OcspException(OcspException.WITHOUT_RESPONSE_FOR_CERTIFICATE);
        }
        CertificateStatus status = this.certStatus.get(certID);
        if (status != CertificateStatus.GOOD) {
            if (status instanceof RevokedInfo) {
                RevokedInfo revokedInfo = (RevokedInfo) status;
                SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
                Time revogationTime = null;
                try {
                    revogationTime = new Time(dateF.parse(revokedInfo.getRevocationTime().getTime()).getTime());
                } catch (ParseException parseException) {
                    throw new OcspException(parseException);
                }
                if (revogationTime.before(this.currentDate)) {
                    throw new OcspException(OcspException.REVOKED_CERTIFICATE);
                }
            }
        }
        if (removeProvider)
            Security.removeProvider("BC");
    }

    /**
     * Busca por uma resposta OCSP
     * @param certificate Certificado a ser verificado
     * @param extensions
     * @throws CertPathValidatorException exceção em caso de erro na verificação
     */
    @Override
    public void check(Certificate certificate, Collection<String> extensions) throws CertPathValidatorException {
        try {
            check(certificate, true);
        } catch (OcspException ocspException) {
            throw new CertPathValidatorException(ocspException);
        }
    }

    /**
     * Retorna o conjunto de extensões adicionais suportadas
     * @return Conjunto de extensões adicionais suportadas
     */
    @Override
    public Set<String> getSupportedExtensions() {
        /*
         * Não há necessidade de especificar nenhuma extensão adicional aqui.
         */
        return null;
    }

    /**
     * Inicializa o verificador
     * @param forward Indica se forward é suportado
     * @throws CertPathValidatorException exceção em caso de erro na inicialização
     */
    @Override
    public void init(boolean forward) throws CertPathValidatorException {
        /*
         * Forward não é suportado, portanto esse init é desnecessário
         */
    }

    /**
     * Retorna se a verificação de forward é suportada
     * @return Indica se forward é suportado
     */
    @Override
    public boolean isForwardCheckingSupported() {
        return false;
    }
}
