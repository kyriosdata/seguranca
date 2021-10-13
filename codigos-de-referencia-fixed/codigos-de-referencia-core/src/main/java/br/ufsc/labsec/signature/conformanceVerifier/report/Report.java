package br.ufsc.labsec.signature.conformanceVerifier.report;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.MimeConstants;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa o relatório de um documento assinado
 */
public class Report {

	private static final String FALSE = "False";
	private static final String TRUE = "True";
	private static final String VERSION = "version";
	/**
	 * Versão do Verificador de Conformidade
	 */
	private String softwareVersion;
	/**
	 * Nome do Verificador
	 */
	private String softwareName;
	/**
	 * Data da verificação
	 */
	private Date verificationDate;
	/**
	 * Fonte da data
	 */
	private String sourceOfDate;
	/**
	 * Nome do arquivo verificado
	 */
	private String sourceFile;
	/**
	 * Fonte da LPA
	 */
	private boolean online;
	/**
	 * Período de validade da LPA
	 */
	private String period;
	/**
	 * Validade da LPA
	 */
	private boolean lpaValid;
	/**
	 * Indica se a LPA está expirada
	 */
	private String lpaExpired;
	/**
	 * Mensagem de erro da LPA
	 */
	private String lpaErrorMessage;
	/**
	 * Versão da LPA
	 */
	private String lpaVersion;
	/**
	 * Lista de relatórios das políticas de assinatura
	 */
	private List<PaReport> paList;
	/**
	 * Lista de relatórios das assinaturas
	 */
	private List<SignatureReport> signatures;
	/**
	 * Número do relatório
	 */
	private int number;

	/**
	 * Enumeração dos tipos de relatório
	 */
	public enum ReportType {
		HTML, PDF
	}

	/**
	 * Construtor da classe
	 */
	public Report() {

		this.paList = new ArrayList<PaReport>();
		this.signatures = new ArrayList<SignatureReport>();
	}

	/**
	 * Atribue a versão do software
	 * @param version A versão do Verificador de Conformidade
	 */
	public void setSoftwareVersion(String version) {
		this.softwareVersion = version;
	}

	/**
	 * Atribue o nome do software
	 * @param name O nome do software
	 */
	public void setSoftwareName(String name) {
		this.softwareName = name;
	}

	/**
	 * Atribue a data de verificação
	 * @param verification A data da verificação
	 */
	public void setVerificationDate(Date verification) {
		this.verificationDate = verification;
	}

	/**
	 * Atribue a fonte da data
	 * @param source A fonte da data
	 */
	public void setSourceOfDate(String source) {
		this.sourceOfDate = source;
	}

	/**
	 * Atribue se a LPA é buscada online
	 * @param online Indica se a LPA é buscada online
	 */
	public void setOnline(boolean online) {
		this.online = online;
	}

	/**
	 * Atribue o período de validade da LPA
	 * @param period O período de validade da LPA
	 */
	public void setPeriod(String period) {
		this.period = period;
	}

	/**
	 * Atribue a validade da LPA
	 * @param valid Indica se a LPA é válida
	 */
	public void setLpaValid(boolean valid) {
		this.lpaValid = valid;
	}

	/**
	 * Atribue a versão da LPA
	 * @param version A versão da LPA
	 */
	public void setLpaVersion(String version) {
		this.lpaVersion = version;
	}

	/**
	 * Atribue o arquivo fonte da assinatura
	 * @param sourceFile O nome do arquivo de assinatura
	 */
	public void setSourceFile(String sourceFile) {
		this.sourceFile = sourceFile;
	}

	/**
	 * Atribue o número do relatório
	 * @param i O número do relatório
	 */
	public void setNumber(int i) {
		this.number = i;
	}

	/**
	 * Adiciona um relatório de uma política de assinatura
	 * @param paReport O relatório a ser adicionado
	 */
	public void addPaReport(PaReport paReport) {
		Iterator<PaReport> iterator = this.paList.iterator();
		boolean notInList = true;
		while (iterator.hasNext() && notInList) {
			notInList = !iterator.next().getOid().equals(paReport.getOid());
		}

		if (notInList) {
			this.paList.add(paReport);
		}
	}

	/**
	 * Adiciona um relatório de assinatura
	 * @param signatureReport O relatório a ser adicionado
	 */
	public void addSignatureReport(SignatureReport signatureReport) {
		this.signatures.add(signatureReport);
	}

	/**
	 * Informa qual o erro que ocoreu na LPA quando sua validação não foi
	 * possível.
	 * @param lpaErrorMessage A mensagem de erro
m	 */
	public void setLpaErrorMessage(String lpaErrorMessage) {
		this.lpaErrorMessage = lpaErrorMessage;
	}

	public void setLpaExpired(String lpaExpired) {
		this.lpaExpired = lpaExpired;
	}

	/**
	 * Gera o documento da classe
	 * @return {@link Document}
	 * @throws Exception exceção na geração do arquivo
	 */
	public Document generate() {
		Document document = null;
		try {
			document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			Application.logger.log(Level.SEVERE, "Problema na construção do documento para geração do relatório", e);
		}

		Element report = document.createElement("report");
		document.appendChild(report);

		Element generalStatus = document.createElement("generalStatus");
		generalStatus.setTextContent(generateGeneralStatus(this.signatures));
		report.appendChild(generalStatus);

        Element number = document.createElement("number");
        number.setTextContent(String.valueOf(this.number));
        report.appendChild(number);

		Element version = document.createElement(VERSION);
		version.setTextContent("1.1");
		report.appendChild(version);

		Element software = document.createElement("software");
		report.appendChild(software);

		Element versionSoftware = document.createElement(VERSION);
		versionSoftware.setTextContent(this.softwareVersion);
		software.appendChild(versionSoftware);

		Element name = document.createElement("name");
		name.setTextContent(this.softwareName);
		software.appendChild(name);

		Element sourceFile = document.createElement("sourceFile");
		sourceFile.setTextContent(this.sourceFile);
		software.appendChild(sourceFile);

		Element date = document.createElement("date");
		report.appendChild(date);

		if (this.verificationDate != null) {
			DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss zzz");
			String verificationDateFormated = df.format(this.verificationDate);

			Element verificationDate = document.createElement("verificationDate");
			verificationDate.setTextContent(verificationDateFormated);
			date.appendChild(verificationDate);
		}

		Element sourceOfDate = document.createElement("sourceOfDate");
		sourceOfDate.setTextContent(this.sourceOfDate);
		date.appendChild(sourceOfDate);

		return this.generateElements(document);

	}

	/**
	 * Gera os ultimos elementos do documento da classe
	 * @param document Document
	 * @return {@link Document}
	 */
	private Document generateElements(Document document) {
		if (this.paList.isEmpty()) {
			return this.generateSignaturesElement(document);
		}

		Element lpa = document.createElement("lpa");
		document.getFirstChild().appendChild(lpa);

		Element online = document.createElement("online");
		lpa.appendChild(online);
		if (this.online)
			online.setTextContent(TRUE);
		else
			online.setTextContent(FALSE);

		Element valid = document.createElement("valid");
		lpa.appendChild(valid);

		if (this.lpaValid)
			valid.setTextContent(TRUE);
		else
			valid.setTextContent(FALSE);

		if (!this.lpaValid) {
			Element lpaErrorMessage = document.createElement("lpaErrorMessage");
			lpaErrorMessage.setTextContent(this.lpaErrorMessage);
			lpa.appendChild(lpaErrorMessage);
		}

		Element period = document.createElement("period");
		lpa.appendChild(period);
		period.setTextContent(this.period);

		Element expired = document.createElement("expired");
		lpa.appendChild(expired);
		expired.setTextContent(this.lpaExpired);

		Element lpaVersion = document.createElement(VERSION);
		lpa.appendChild(lpaVersion);
		lpaVersion.setTextContent(this.lpaVersion);

		Element pas = document.createElement("pas");
		document.getFirstChild().appendChild(pas);

		for (PaReport paReport : this.paList) {
			pas.appendChild(paReport.generate(document));
		}

		return this.generateSignaturesElement(document);
	}

	/**
	 * Gera os elementos das assinaturas
	 * @param document Document
	 * @return {@link Document}
	 */
	private Document generateSignaturesElement(Document document) {
		Element signatures = document.createElement("signatures");
		document.getFirstChild().appendChild(signatures);

		for (SignatureReport signature : this.signatures) {

			try {
				signatures.appendChild(signature.generateSignatureElement(document));
			} catch (DOMException e) {
				Application.logger.log(Level.SEVERE, "Erro ao gerar documento",
						e);
			} catch (SignatureAttributeException e) {
				Application.logger.log(Level.SEVERE,
						"Erro ao gerar elemento de assinatura", e);
			}
		}

		return document;
	}

	/**
	 * Retorna a mensagem de validade do documento assinado, considerando a lista das suas assinaturas
	 * @param signatures A lista de assinaturas de um documento
	 * @return A mensagem de validade de acordo com as assinaturas
	 */
	public static String generateGeneralStatus(List<SignatureReport> signatures) {
		String status = "Aprovado";
		for (SignatureReport signature : signatures) {
			if (signature.validityStatus() == SignatureReport.SignatureValidity.Invalid) {
				return "Reprovado";
			}
			else if (signature.validityStatus() == SignatureReport.SignatureValidity.Indeterminate) {
				status = "Indeterminado";
			}
		}
		return status;
	}

	/**
	 * Gera o relatório de acordo com seu tipo
	 * @param reportType O tipo de relatório
	 * @param reportPath
	 * @param stylePath
	 */
	public static void generateReport(ReportType reportType, String reportPath, InputStream stylePath) {

		 if(reportType.equals(ReportType.HTML)) {
	            try {
	                TransformerFactory factory = TransformerFactory.newInstance();
	                Source xslt = new StreamSource(stylePath);
	                Transformer transformer = factory.newTransformer(xslt);

	                Source text = new StreamSource(new File(reportPath));
	                transformer.transform(text, new StreamResult(new File(reportPath + ".html")));

	            } catch (TransformerConfigurationException e) {
	                // TODO Auto-generated catch block
	                e.printStackTrace();
	            } catch (TransformerException e) {
	                // TODO Auto-generated catch block
	                e.printStackTrace();
	            }
	        } else if(reportType.equals(ReportType.PDF)) {
	            try {

	                Application.logger.log(Level.CONFIG,"Preparing pdf...");

	                // Setup input and output files
	                File xmlfile = new File(reportPath);
	                File pdffile = new File(reportPath.substring(0, reportPath.lastIndexOf('.')) + ".pdf");

	                // configure fopFactory as desired
	                final FopFactory fopFactory = FopFactory.newInstance();

	                // configure foUserAgent as desired
	                FOUserAgent foUserAgent = fopFactory.newFOUserAgent();

	                // Setup output
	                OutputStream out = new java.io.FileOutputStream(pdffile);
	                out = new java.io.BufferedOutputStream(out);

	                try {
	                        // Construct fop with desired output format
	                        Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, out);

	                        // Setup XSLT
	                        TransformerFactory factory = TransformerFactory.newInstance();
	                        Transformer transformer = factory.newTransformer(new StreamSource(stylePath));

	                        // Set the value of a <param> in the stylesheet
	                        transformer.setParameter("versionParam", "2.0");

	                        // Setup input for XSLT transformation
	                        Source src = new StreamSource(xmlfile);

	                        // Resulting SAX events (the generated FO) must be piped through to FOP
	                        Result res = new SAXResult(fop.getDefaultHandler());

	                        // Start XSLT transformation and FOP processing
	                        transformer.transform(src, res);

	                        // Move xmlfile to /tmp
	                        xmlfile.renameTo(xmlfile.createTempFile("xml", "tmp"));
	                } finally {
	                        out.close();
	                }

	                Application.logger.log(Level.CONFIG, "Success!");
	        } catch (Exception e) {
	        	Application.logger.log(Level.SEVERE, "Erro ao gerar o relatório em PDF.", e);

	        }
	        }


	}

	/**
	 * Retorna a versão do Verificador
	 * @return A versão do software
	 */
	public String getSoftwareVersion() {
		return softwareVersion;
	}

	/**
	 * Retorna o nome do software
	 * @return O nome do software
	 */
	public String getSoftwareName() {
		return softwareName;
	}

	/**
	 * Retorna a data da verificação
	 * @return A data da verificação
	 */
	public Date getVerificationDate() {
		return verificationDate;
	}

	/**
	 * Retorna a fonte da data
	 * @return A fonte da data
	 */
	public String getSourceOfDate() {
		return sourceOfDate;
	}

	/**
	 * Retorna o nome do arquivo de assinatura
	 * @return O nome do arquivo de assinatura
	 */
	public String getFileName() {
		return sourceFile;
	}

	/**
	 * Retorna se a LPA foi buscada online
	 * @return Indica se a LPA foi buscada online
	 */
	public boolean isOnline() {
		return online;
	}

	/**
	 * Retorna o período de validade da LPA
	 * @return O período de validade da LPA
	 */
	public String getPeriod() {
		return period;
	}

	/**
	 * Retorna se a LPA é válida
	 * @return Indica se a LPA é válida
	 */
	public boolean isLpaValid() {
		return lpaValid;
	}

	/**
	 * Retorna a mensagem de erro caso a validação da LPA
	 * não tenha sido possível
	 * @return A mensagem de erro da LPA
	 */
	public String getLpaErrorMessage() {
		return lpaErrorMessage;
	}

	/**
	 * Retorna a versão da LPA
	 * @return A versão da LPA
	 */
	public String getLpaVersion() {
		return lpaVersion;
	}

	/**
	 * Retorna a lista de relatórios de validação de políticas de assinatura
	 * @return A lista de relatórios de políticas de assinatura
	 */
	public List<PaReport> getPaList() {
		return paList;
	}

	/**
	 * Retorna a lista de relatórios de assinaturas
	 * @return A lista de relatórios de assinaturas
	 */
	public List<SignatureReport> getSignatures() {
		return signatures;
	}

	/**
	 * Retorna se a LPA está expirada
	 * @return Indica se a LPA está expirada
	 */
	public String isLpaExpired() {
		return lpaExpired;
	}

	/**
	 * Insere informações do relatório no log
	 */
	public void log() {

		Application.loggerInfo.log(Level.INFO, "Nome do software: " + this.softwareName);
		Application.loggerInfo.log(Level.INFO, "Versão do software: " + this.softwareVersion);
		Application.loggerInfo.log(Level.INFO,
				"Data de verificação: " + this.verificationDate.toString());
		Application.loggerInfo.log(Level.INFO, "Fonte da data: " + this.sourceOfDate);
		Application.loggerInfo.log(Level.INFO, "Arquivo: " + this.sourceFile);

		if (this.lpaVersion != null) {
			String lpaOnOff = this.online ? "on" : "off";
			Application.loggerInfo.log(Level.INFO, "LPA é " + lpaOnOff + "line.");

			String lpaVal = this.lpaValid ? "" : "in";
			Application.loggerInfo.log(Level.INFO,
					"LPA " + lpaVal + "válida. " + Objects.toString(this.lpaErrorMessage, ""));

			Application.loggerInfo.log(Level.INFO, "Período da LPA: " + this.period);
			Application.loggerInfo.log(Level.INFO, "Versão da LPA: " + this.lpaVersion);
		}

		for (PaReport pa : this.paList) {
			pa.log();
		}

		for (SignatureReport sr : this.signatures) {
			sr.log();
		}

	}

}
