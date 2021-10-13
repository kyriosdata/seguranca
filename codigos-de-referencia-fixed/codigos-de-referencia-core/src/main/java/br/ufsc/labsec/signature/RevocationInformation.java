package br.ufsc.labsec.signature;

import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;

/**
 * Interface RevocationInformation
 *
 */
public interface RevocationInformation {

	class CRLResult {
		public CRL crl;
		public boolean fromWeb;
	}
	
    /**
     * Retorna a CRL de um certificado.
     * 
     * @param certificate Certificado que se deseja a CRL.
     * @return A Crl do certificado.
     */
	CRLResult getCRLFromCertificate(Certificate certificate, Time timeReference);

	default CRLResult getCRLFromCertificate(Certificate certificate) {
		Time time = new Time(SystemTime.getSystemTime());
		return getCRLFromCertificate(certificate, time);
	}

    void addCrl(List<X509Certificate> certValuesCertificates, List<X509CRL> crlsList);
}
