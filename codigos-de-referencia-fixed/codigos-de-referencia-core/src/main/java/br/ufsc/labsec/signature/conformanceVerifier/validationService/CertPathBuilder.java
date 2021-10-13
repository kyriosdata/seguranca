/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.GregorianCalendar;
import java.util.Set;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Classe responsável por criar caminhos de certificação
 */
public class CertPathBuilder {
	private static final String CERT_PATH_ERROR = "Não foi possível criar o caminho de certificação";

	/**
	 * Constrói o caminho de certificação do certificado indicado
	 * 
	 * @param certificate O certificado final do caminho de certificação
	 * @param certStore O objeto que contêm os certificados e as LCRs para a
	 *            construção do caminho de certificação
	 * @param trustAnchors As possíveis âncoras de confiança para o caminho de
	 *            certificação
	 * @param isRevocationEnabled Indica se o caminho de certificfação deve ser validado
	 *            enquanto está sendo montado
	 * @return O caminho de certificação criado
	 * @throws CertificationPathException exceção caso não seja possivel criar o caminho de certificação
	 */
	public static CertPath buildPath(X509Certificate certificate, CertStore certStore, Set<TrustAnchor> trustAnchors,
			Time timeReference, boolean isRevocationEnabled) throws CertificationPathException {

		CertPath certPath = null;
		PKIXBuilderParameters pkixBuilderParams = null;
		X509CertSelector certSelector = new X509CertSelector();
		certSelector.setCertificate(certificate);
		try {
			pkixBuilderParams = new PKIXBuilderParameters(trustAnchors, certSelector);
		} catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
			throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
					invalidAlgorithmParameterException);
		}
		pkixBuilderParams.addCertStore(certStore);
		pkixBuilderParams.setRevocationEnabled(isRevocationEnabled);
		pkixBuilderParams.setDate(timeReference);
		// pkixBuilderParams.setSigProvider("BC");

		java.security.cert.CertPathBuilder certPathBuilder;
		try {
			certPathBuilder = java.security.cert.CertPathBuilder.getInstance("PKIX", new BouncyCastleProvider());
		} catch (NoSuchAlgorithmException noSuchAlgorithmException) {
			throw new CertificationPathException(CertificationPathException.NO_SUCH_ALGORITHM,
					noSuchAlgorithmException);
		}
		try {
			if (certificate.getNotAfter().before(timeReference)) {
				// Certificate expirated
				/*
				 * Assumes a date one day after the certificate issue so the
				 * certPathBuilder works. Raises an exception to let the caller
				 * know that the certPath is expired.
				 */

				GregorianCalendar assumedTimeReference = new GregorianCalendar();
				assumedTimeReference.setTime(certificate.getNotBefore());
				assumedTimeReference.add(GregorianCalendar.DAY_OF_MONTH, 1);
				pkixBuilderParams.setDate(assumedTimeReference.getTime());

				certPath = certPathBuilder.build(pkixBuilderParams).getCertPath();
				throw new CertificationPathException(CertificationPathException.EXPIRED_CERTIFICATE, certPath);
			} else if (certificate.getNotBefore().after(timeReference)) {
				// Certificate not valid yet!?
				/*
				 * Assumes a date one day after the certificate issue so the
				 * certPathBuilder works. Raises an exception to let the caller
				 * know that the certPath is not valid yet.
				 */

				GregorianCalendar assumedTimeReference = new GregorianCalendar();
				assumedTimeReference.setTime(certificate.getNotBefore());
				assumedTimeReference.add(GregorianCalendar.DAY_OF_MONTH, 1);
				pkixBuilderParams.setDate(assumedTimeReference.getTime());

				certPath = certPathBuilder.build(pkixBuilderParams).getCertPath();
				throw new CertificationPathException(CertificationPathException.CERTIFICATE_NOT_VALID_YET, certPath);
			} else {
				certPath = certPathBuilder.build(pkixBuilderParams).getCertPath();
			}
		} catch (CertPathBuilderException certPathBuilderException) {
			Application.logger.log(Level.WARNING, CERT_PATH_ERROR, certPathBuilderException.getMessage());
			throw new CertificationPathException(CertificationPathException.PROBLEM_TO_VALIDATE_CERTPATH,
					certPathBuilderException);
		} catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
			Application.logger.log(Level.WARNING, CERT_PATH_ERROR, invalidAlgorithmParameterException);
			throw new CertificationPathException(CertificationPathException.INVALID_ALGORITHM_PARAMS_OR_ALGORITHM,
					invalidAlgorithmParameterException);
		}

		return certPath;
	}
}
