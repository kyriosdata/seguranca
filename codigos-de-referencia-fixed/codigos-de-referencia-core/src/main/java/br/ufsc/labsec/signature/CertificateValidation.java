package br.ufsc.labsec.signature;

import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.sql.Time;
import java.util.Date;
import java.util.List;
import java.util.Set;

import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertRevReq;

/**
 * 
 * Interface responsável pela validação de certificados.
 *
 */
public interface CertificateValidation {

    /**
     * 
     * Possíveis resultados de uma validação de um certificado.
     *
     */
    public enum ValidationResult {
        valid("Válido"), invalid("Inválido"), crlMissing("LCR faltando"), invalidCrl("LCR inválida"), validationNotPossible("Validação não é possível");
        private String message;
        private Date revocationDate;
        private Certificate certWithError;
        
        ValidationResult(String message) {
            this.message = message;
        }

        public String getMessage(){
            return this.message;
        }

		 public void setMessage(String message) {
        	this.message = message;
        }
		 
		public void setRevocationDate(Date revocationDate) {
			this.revocationDate = revocationDate;
		}
		
		public Date getRevocationDate() {
			return this.revocationDate;
		}

		public void setRevocationCertificate(Certificate certWithError) {
			this.certWithError = certWithError;
		}

		public Certificate getRevocationCertificate() {
			return this.certWithError;
		}

    }

    /**
     * 
     * Realiza a validação de um certificado.
     * 
     * @param certicate O certificado.
     * @param trustAnchors Os truts anchors.
     * @param revocationRequirements Requerimentos de revogação.
     * @param timeReference Tempo de referencia.
     * @param sigReport Relatório da assinatura.
     * @return {@link ValidationResult} Resultado da validação.
     */
    public ValidationResult validate(Certificate certicate, Set<TrustAnchor> trustAnchors, CertRevReq revocationRequirements,
            Time timeReference, SignatureReport sigReport);

    /**
     * Retorna o certificado que provocou o erro, caso exista.
     * 
     * @return O certificado que provocou o erro.
     */
    public Certificate getCertificateWithError();

    /**
     * Retorna o CRL que provocou o erro, caso exista.
     * 
     * @return A CRL que provocou o erro.
     */
    public CRL getCrlWithError();

    /**
     * Retorna a mensagem de erro, caso ocorreu algum erro.
     * 
     * @return A mensagem de erro.
     */
    public String getMessageError();

	/**
	 * Retorna as LCR que satisfaçam a condição
	 * @param selector {@link CRLSelector} que indica a condição de busca das LCRs
	 * @return A lista de LCRs que satisfizeram a condição de busca
	 */
    public List<X509CRL> getCRLs(X509CRLSelector selector);

	/**
	 * Retorna as LCR que satisfaçam a condição
	 * @param selector {@link CRLSelector} que indica a condição de busca das LCRs
	 * @param timeReference Data em que a LCR deve ser válida
	 * @return A lista de LCRs que satisfizeram a condição de busca
	 */
    public List<X509CRL> getCRLs(X509CRLSelector selector, Time timeReference); 
    
    /**
     * Cria o caminho de certificação.
     * 
     * @param certificate O certificado.
     * @param trustAnchors  Os trust anchors
     * @param timeReference Tempo de referencia.
     * @return O caminho de certificação.
     */
    public CertPath generateCertPath(Certificate certificate, Set<TrustAnchor> trustAnchors, Time timeReference);

    /**
     * Cria o caminho de certificação sem uso de armazenamento.
     *
     * @param certificate O certificado.
     * @param trustAnchors  Os trust anchors
     * @param timeReference Tempo de referencia.
     * @return O caminho de certificação.
     */
    public CertPath generateCertPathNoSave(Certificate certificate, Set<TrustAnchor> trustAnchors, Time timeReference);
}
