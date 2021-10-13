package br.ufsc.labsec.signature.conformanceVerifier.report;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Esta classe representa o relatório da validação de certificados e CRLs de uma assinatura
 */
public class ValidationDataReport {

    private static final String SERIAL_NUMBER = "serialNumber";
    private static final String ISSUER_NAME = "issuerName";
    private static final String VALID = "validSignature";
    private static final String FALSE = "False";
    private static final String TRUE = "True";
    private static final String ONLINE = "online";
	private static final String CRL_DATES = "dates";
	private static final String NEXT_UPDATE = "nextUpdate";
	private static final String THIS_UPDATE = "thisUpdate";
	private static final String NOT_BEFORE = "notBefore";
	private static final String NOT_AFTER = "notAfter";
	private static final String EXPIRED = "expired";
	private static final String REVOKED = "revoked";
	/**
	 * Indica se o certificado foi obtido por download
	 */
    private boolean certificateOnline;
	/**
	 * Validade do certificado
	 */
	private boolean validCertificate;
	/**
	 * Motivo da invalidação do certificado
	 */
    private String invalidCertificateReason;
	/**
	 * Nome do dono do certificado
	 */
	private String certificateSubjectName;
	/**
	 * Nome do emissor do certificado
	 */
    private String certificateIssuerName;
	/**
	 * Número de série do certificado
	 */
	private String certificateSerialNumber;
	/**
	 * Início do período de validade do certificado
	 */
    private Date notBefore;
	/**
	 * Fim do período de validade do certificado
	 */
	private Date notAfter;
	/**
	 * Indica se há CRL
	 */
    private boolean crlFlag;
	/**
	 * Indica se a CRL foi obtida por download
	 */
	private boolean crlOnline;
	/**
	 * Nome do emissor da CRL
	 */
    private String crlIssuerName;
	/**
	 * Número de série da CRL
	 */
	private String crlSerialNumber;
	/**
	 * Validade da CRL
	 */
    private boolean validCrl;
	/**
	 * Indica se há OCSP
	 */
	private boolean ocspFlag;
	/**
	 * Indica se o OCSP foi obtido por download
	 */
    private boolean ocspOnline;
	/**
	 * Validade do OCSP
	 */
	private boolean validOcsp;
	/**
	 * Data da próxima atualização da CRL
	 */
	private Date nextUpdate;
	/**
	 * Data da última atualização da CRL
	 */
	private Date thisUpdate;
	/**
	 * Indica se o certificado foi revogado
	 */
	private boolean isRevoked;

    /**
     * Atribue o número de série da CRL
     * 
     * @param serialNumber O número de série da CRL
     */
    public void setCrlSerialNumber(String serialNumber) {
        this.crlSerialNumber = serialNumber;
        this.crlFlag = true;
    }

	/**
	 * Atribue a data de início do período de validade do certificado
	 * @param notBefore A data de início do período de validade do certificado
	 */
	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	/**
	 * Atribue a data de fim do período de validade do certificado
	 * @param notAfter A data de fim do período de validade do certificado
	 */
	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

    /**
     * Atribue se a CRL foi obtida do cache ou através de download
     * 
     * @param online Se a CRL foi obtida por download
     */
    public void setCrlOnline(boolean online) {
        this.crlOnline = online;
        this.crlFlag = true;
    }

    /**
     * Atribue se a CRL é válida
     * 
     * @param validCrl A validade da CRL
     */
    public void setValidCrl(boolean validCrl) {
        this.validCrl = validCrl;
        this.crlFlag = true;
    }

    /**
     * Atribue o nome do emissor da CRL
     * 
     * @param name O nome do emissor da CRL
     */
    public void setCrlIssuerName(String name) {
        this.crlIssuerName = name;
    }

    /**
     * Atribue se certificado foi obtido do cache ou através de download
     * 
     * @param online Se o certificado foi obtido por download
     */
    public void setCertificateOnline(boolean online) {
        this.certificateOnline = online;
    }

    /**
     * Atribue se o certificado é válido
     * 
     * @param validCert A validade do certificado
     */
    public void setValidCertificate(boolean validCert) {
        this.validCertificate = validCert;
    }

    /**
     * Atribue a razão do certificado ser inválido
     * 
     * @param reason A razão do certificado ser inválido
     */
    public void setInvalidCertificateReason(String reason) {
        this.invalidCertificateReason = reason;
    }

    /**
     * Atribue o nome do dono do certificado
     * 
     * @param name O nome do dono do certificado
     */
    public void setCertificateSubjectName(String name) {
        this.certificateSubjectName = name;
    }

    /**
     * Atribue o nome do emissor do certificado
     * 
     * @param name O nome do emissor do certificado
     */
    public void setCertificateIssuerName(String name) {
        this.certificateIssuerName = name;
    }

    /**
     * Atribue o número de série do certificado
     * 
     * @param number O número de série do certificado
     */
    public void setCertificateSerialNumber(String number) {
        this.certificateSerialNumber = number;
    }

    /**
     * Atribue se OCSP foi obtido do cache ou através de download
     * 
     * @param online Se o OCSP foi obtido por download
     */
    public void setOcspOnline(boolean online) {
        this.ocspOnline = online;
        this.ocspFlag = true;
    }

    /**
     * Atribue se o OCSP é válido
     * 
     * @param validOcsp Validade do OCSP
     */
    public void setValidOcsp(boolean validOcsp) {
        this.validOcsp = validOcsp;
        this.ocspFlag = true;
    }

    /**
     * Retorna se há CRL
     * 
     * @return Indica a presença de CRL
     */
    public Boolean hasCrl() {
        return this.crlFlag;
    }

    /**
     * Retorna se há OCSP
     * 
     * @return Indica a presença de OCSP
     */
    public Boolean hasOcsp() {
        return this.ocspFlag;
    }

    /**
     * Gera o elemento OCSP
     * 
     * @param document Document
     * @return {@link Element}
     */
    public Element generateOcspElement(Document document) {

        Element ocsp = document.createElement("ocsp");

        Element ocspOnline = document.createElement(ONLINE);
        ocsp.appendChild(ocspOnline);
        if (this.ocspOnline)
            ocspOnline.setTextContent(TRUE);
        else
            ocspOnline.setTextContent(FALSE);

        Element validOcsp = document.createElement(VALID);
        ocsp.appendChild(validOcsp);
        if (this.validOcsp)
            validOcsp.setTextContent(TRUE);
        else
            validOcsp.setTextContent(FALSE);

        return ocsp;
    }

    /**
     * Gerar elemento crl
     * 
     * @param document Document
     * @return {@link Element}
     */
    public Element generateCrlElement(Document document) {
        if (this.crlIssuerName != null) {
            Element crl = document.createElement("crl");

            Element crlOnline = document.createElement(ONLINE);
            crl.appendChild(crlOnline);
            if (this.crlOnline)
                crlOnline.setTextContent(TRUE);
            else
                crlOnline.setTextContent(FALSE);

            Element validCrl = document.createElement(VALID);
            crl.appendChild(validCrl);
            if (this.validCrl)
                validCrl.setTextContent(TRUE);
            else
                validCrl.setTextContent(FALSE);

            Element crlIssuerName = document.createElement(ISSUER_NAME);
            crlIssuerName.setTextContent(this.crlIssuerName);
            crl.appendChild(crlIssuerName);

            Element serialNumber = document.createElement(SERIAL_NUMBER);
            crl.appendChild(serialNumber);
            serialNumber.setTextContent(this.crlSerialNumber);
            
		    DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss zzz");
            
            String nextUpdateDate = df.format(this.nextUpdate);
            String thisUpdateDate = df.format(this.thisUpdate);
            
            Element crlDates = document.createElement(CRL_DATES);
            Element nextUpdate = document.createElement(NEXT_UPDATE);
            crlDates.appendChild(nextUpdate);
            nextUpdate.setTextContent(nextUpdateDate);
            
            Element thisUpdate = document.createElement(THIS_UPDATE);
            crlDates.appendChild(thisUpdate);
            thisUpdate.setTextContent(thisUpdateDate);
            
            crl.appendChild(crlDates);

            return crl;
        }

        return null;
    }

    /**
     * Gera elemento do certificado
     * 
     * @param document Document
     * @return {@link Element}
     */
    public Element generateCertificateElement(Document document) {

        if (this.certificateSubjectName != null) {
            Element certificate = document.createElement("certificate");

            Element certificateOnline = document.createElement(ONLINE);
            certificate.appendChild(certificateOnline);
            if (this.certificateOnline)
                certificateOnline.setTextContent(TRUE);
            else
                certificateOnline.setTextContent(FALSE);

            Element validCertificate = document.createElement(VALID);
            certificate.appendChild(validCertificate);
            if (this.validCertificate)
                validCertificate.setTextContent(TRUE);
            else {
                validCertificate.setTextContent(FALSE);
                Element invalidCertificateReason = document.createElement("invalidCertificateReason");
                invalidCertificateReason.setTextContent(this.invalidCertificateReason);
                certificate.appendChild(invalidCertificateReason);
            }

            Element certificateSubjectName = document.createElement("subjectName");
            certificateSubjectName.setTextContent(this.certificateSubjectName);
            certificate.appendChild(certificateSubjectName);

            Element certificateIssuerName = document.createElement(ISSUER_NAME);
            certificateIssuerName.setTextContent(this.certificateIssuerName);
            certificate.appendChild(certificateIssuerName);

            Element serialNumber = document.createElement(SERIAL_NUMBER);
            serialNumber.setTextContent(this.certificateSerialNumber);
            certificate.appendChild(serialNumber);

			DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss zzz");
            
            String notBeforeDate = df.format(this.notBefore);
            String notAfterDate = df.format(this.notAfter);
            
            Element notBefore = document.createElement(NOT_BEFORE);
            notBefore.setTextContent(notBeforeDate);
            certificate.appendChild(notBefore);
            
            Element notAfter = document.createElement(NOT_AFTER);
            notAfter.setTextContent(notAfterDate);
            certificate.appendChild(notAfter);
            
            Element isExpired = document.createElement(EXPIRED );
            if(isExpired()){
            	isExpired.setTextContent(TRUE);
            }else{
            	isExpired.setTextContent(FALSE);
            }
            certificate.appendChild(isExpired);

			Element isRevoked = document.createElement(REVOKED);
			isRevoked.setTextContent(this.isRevoked ? TRUE : FALSE);
			certificate.appendChild(isRevoked);

            return certificate;
        }

        return null;
    }

	/**
	 * Atribue a data da próxima atualização da CRL
	 * @param nextUpdate A data da próxima atualização da CRL
	 */
	public void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	/**
	 * Atribue a data da última versão da CRL
	 * @param thisUpdate A data da última versão da CRL
	 */
	public void setThisUpdate(Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}

	/**
	 * Comparação entre dois objetos ValidationDataReport
	 * @param obj Objeto a ser comparado
	 * @return Se os objetos são iguais
	 */
	@Override
	public boolean equals(Object obj) {
		
		ValidationDataReport o = (ValidationDataReport) obj;
		
		if(this.certificateIssuerName != null) {
			return this.certificateIssuerName.compareTo(o.certificateIssuerName)==0 &&
					this.certificateSerialNumber.compareTo(o.certificateSerialNumber)==0;
		} else {
			return this.crlIssuerName.compareTo(o.crlIssuerName)==0
					&& this.crlSerialNumber.compareTo(o.crlSerialNumber)==0;
		}
		
	}

	@Override
	public int hashCode() {
		/**
		 * FIXME `equals` method breaks if Objects.hash() is used on the first condition
		 *
		 *  We have no idea why that happens, but it probably has something to do with
		 *  copy constructors.
		 */
		return this.certificateIssuerName != null
				? this.certificateIssuerName.hashCode() * this.certificateSerialNumber.hashCode()
				: Objects.hash(this.crlIssuerName, this.crlSerialNumber);
	}

	/**
	 * Retorna o nome do emissor do certificado
	 * @return O nome do emissor do certificado
	 */
	public String getCertificateIssuerName() {
		return certificateIssuerName;
	}

	/**
	 * Retorna o número de série do certificado
	 * @return O número de série do certificado
	 */
	public String getCertificateSerialNumber() {
		return certificateSerialNumber;
	}

	/**
	 * Retorna o nome do dono do certificado
	 * @return O nome do dono do certificado
	 */
	public String getCertificateSubjectName() { return certificateSubjectName;}

	/**
	 * Retorna o nome do emissor da CRL
	 * @return O nome do emissor da CRL
	 */
	public String getCrlIssuerName() {return crlIssuerName;}

	/**
	 * Atribue revogação ao certificado
	 * @param b Se o certificado foi revogado
	 */
	public void setRevoked(boolean b) {
		this.isRevoked = b;
	}

	/**
	 * Retorna a validade do certificado
	 * @return A validade do certificado
	 */
	public boolean isValidCertificate() {
        return this.validCertificate;
    }

	/**
	 * Retorna a data de fim do período de validade do certificado
	 * @return A data de fim do período de validade do certificado
	 */
    public Date getNotAfter() {
        return this.notAfter;
    }

	/**
	 * Retorna se o certificado está expirado
	 * @return Se o certificado está expirado
	 */
    public boolean isExpired() {
        return this.notAfter.before(new Date());
    }
}
