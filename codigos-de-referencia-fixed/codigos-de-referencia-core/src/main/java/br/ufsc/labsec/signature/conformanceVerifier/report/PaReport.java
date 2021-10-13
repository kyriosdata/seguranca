package br.ufsc.labsec.signature.conformanceVerifier.report;

import java.util.logging.Level;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import br.ufsc.labsec.component.Application;

/**
 * Esta classe representa o relatório de uma política de assinatura
 */
public class PaReport {

	private static final String FALSE = "False";
	private static final String TRUE = "True";
	/**
	 * Indica se PA foi obtida por download
	 */
	private boolean paOnline;
	/**
	 * OID da PA
	 */
	private String oid;
	/**
	 * Validade da LPA
	 */
	private boolean validLpa;
	/**
	 * Validade da PA
	 */
	private boolean validPa;
	/**
	 * Período de validade da PA
	 */
	private String paPeriod;
	/**
	 * PA revogada
	 */
	private boolean paRevoked;
	/**
	 * PA expirada
	 */
	private boolean paExpired;
	/**
	 * Erro na PA
	 */
	private String paError;

	/**
	 * Atribue se PA foi obtida da cache ou por download
	 * @param online se PA foi obtida por download
	 */
	public void setPaOnline(boolean online) {
		this.paOnline = online;
	}

	/**
	 * Atribue o OID
	 * @param oid O OID da PA
	 */
	public void setOid(String oid) {
		this.oid = oid;
	}

	/**
	 * Atribue a validade da LPA
	 * @param validLpa A validade da LPA
	 */
	public void setValidOnLpa(boolean validLpa) {
		this.validLpa = validLpa;
	}

	/**
	 * Atribue a validade da PA
	 * @param validPa A validade da PA
	 */
	public void setValidPa(boolean validPa) {
		this.validPa = validPa;
	}

	/**
	 * Atribue período de validade da PA
	 * @param paPeriod O período de validade da PA
	 */
	public void setPaPeriod(String paPeriod) {
		this.paPeriod = paPeriod;
	}

	/**
	 * Atribue se a PA está expirada
	 * @param paExpired Se a PA está expirada
	 */
	public void setPaExpired(boolean paExpired) {
		this.paExpired = paExpired;
	}

	/**
	 * Atribue se a PA foi revogada
	 * @param paRevoked Se a PA foi revogada
	 */
	public void setPaRevoked(boolean paRevoked) {
		this.paRevoked = paRevoked;
	}

	/**
	 * Atribue a mensagem de erro da PA
	 * @param error A mensagem de erro da PA
	 */
	public void setPaError(String error) {this.paError = error; }

	/**
	 * Gera elemento da classe
	 * @param document Document
	 * @return {@link Element}
	 */
	public Element generate(Document document) {
		Element pa = document.createElement("pa");

		Element paOnline = document.createElement("online");
		pa.appendChild(paOnline);
		if (this.paOnline)
			paOnline.setTextContent(TRUE);
		else
			paOnline.setTextContent(FALSE);

		Element oid = document.createElement("oid");
		pa.appendChild(oid);
		oid.setTextContent(this.oid);

		Element validLpa = document.createElement("validLpa");
		pa.appendChild(validLpa);
		if (this.validLpa)
			validLpa.setTextContent(TRUE);
		else
			validLpa.setTextContent(FALSE);

		Element validPa = document.createElement("valid");
		pa.appendChild(validPa);
		if (this.validPa)
			validPa.setTextContent(TRUE);
		else
			validPa.setTextContent(FALSE);

		Element paPeriod = document.createElement("period");
		pa.appendChild(paPeriod);
		paPeriod.setTextContent(this.paPeriod);

		Element revokedPa = document.createElement("revoked");
		pa.appendChild(revokedPa);
		if (this.paRevoked)
			revokedPa.setTextContent(TRUE);
		else
			revokedPa.setTextContent(FALSE);

		Element expiredPa = document.createElement("expired");
		pa.appendChild(expiredPa);
		if (this.paExpired)
			expiredPa.setTextContent(TRUE);
		else
			expiredPa.setTextContent(FALSE);

		Element paError = document.createElement("error");
		pa.appendChild(paError);
		paError.setTextContent(this.paError);
		
		return pa;
	}

	/**
	 * Retorna se a PA foi obtida por download ou por cache
	 * @return Se a PA foi obtida por download
	 */
	public boolean getPaOnline() {
		return this.paOnline;
	}

	/**
	 * Retorna o OID da PA
	 * @return O OID da PA
	 */
	public String getOid() {
		return this.oid;
	}

	/**
	 * Retorna a validade da LPA
	 * @return A validade da LPA
	 */
	public boolean getValidLpa() {
		return this.validLpa;
	}

	/**
	 * Retorna a validade da PA
	 * @return A validade da PA
	 */
	public boolean getValidPa() {
		return this.validPa;
	}

	/**
	 * Retorna o período de validade da PA
	 * @return O período de validade da PA
	 */
	public String getPaPeriod() {
		return this.paPeriod;
	}

	/**
	 * Retorna se a PA está expirada
	 * @return Se a PA está expirada
	 */
	public boolean getPaExpired() {
		return paExpired;
	}

	/**
	 * Retorna se a PA foi revogada
	 * @return Se a PA foi revogada
	 */
	public boolean getPaRevoked() {
		return paRevoked;
	}

	/**
	 * Insere informações da PA e LPA no log
	 */
	public void log() {

		String paOnOff = this.paOnline ? "on" : "off";
		Application.loggerInfo.log(Level.INFO, "PA é " + paOnOff + "line.");

		Application.loggerInfo.log(Level.INFO, "Política: " + this.oid);

		String paLpa = this.validLpa ? "" : "não ";
		Application.loggerInfo.log(Level.INFO, "PA " + paLpa + "íntegra segundo LPA.");

		String paInt = this.validPa ? "" : "não ";
		Application.loggerInfo.log(Level.INFO, "PA " + paInt + "é íntegra.");

		Application.loggerInfo.log(Level.INFO, "Período da PA: " + this.paPeriod);

	}

}
