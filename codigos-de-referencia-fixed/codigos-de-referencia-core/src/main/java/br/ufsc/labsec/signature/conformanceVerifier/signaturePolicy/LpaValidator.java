package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.exceptions.LpaException;

/**
 * Esta classe é responsável pela validação de uma Lista de Políticas de Assinatura (LPA)
 */
public class LpaValidator {

	private static final String NO_SIGNATURE_FOUND = "Não foi encontrada nenhuma assinatura no documento XML.";
	private static final String UNABLE_TO_CONNECT_TO_LPA = "Não foi possível se conectar à pagina da LPA indicada.";
	private static final String INVALID_CMS = "CMS inválido.";
	private static final String MALFORMED_URL = "A URL da assinatura está mal formada.";
	private static final String FALSE = "False";
	private static final String TRUE = "True";
	/**
	 * Relatório da verificação
	 */
	private Report report;
	/**
	 * A LPA a ser validada
	 */
	private Lpa lpa;
	/**
	 * Componente de política de assinatura
	 */
	private SignaturePolicyComponent signaturePolicyComponent;
	/**
	 * Instância do validador
	 */
	private static LpaValidator instance;

	/**
	 * Construtor
	 * @param lpa A LPA a ser validada
	 * @param report O relatório de validação
	 * @param signaturePolicyComponent O componente de políticas de assinatura
	 */
	LpaValidator(Lpa lpa, Report report, SignaturePolicyComponent signaturePolicyComponent) {
		this.lpa = lpa;
		this.report = report;
		this.signaturePolicyComponent = signaturePolicyComponent;
		instance = this;
	}

	/**
	 * Retorna a instância do validador
	 * @param lpa A LPA a ser validada
	 * @param report O relatório de validação
	 * @param signaturePolicyComponent O componente de políticas de assinatura
	 * @return A instância do validador
	 */
	public static LpaValidator getInstance(Lpa lpa, Report report, SignaturePolicyComponent signaturePolicyComponent) {
		if (instance == null) {
			instance = new LpaValidator(lpa, report, signaturePolicyComponent);
		}
		return instance;
	}

	/**
	 * Valida a LPA
	 * @param type O tipo da LPA
	 */
	public void validate(AdESType type) {
        switch (type) {
            case XAdES:
                validateXml();
                break;
            case CAdES:
                validateASN1OfType("CAdES");
                break;
            case PAdES:
                validateASN1OfType("PAdES");
        }
	}

	/**
	 * Valida a LPA no formato XML
	 */
	private void validateXml() {
		reportDefaultInformations(this.report);

		String lpaSignatureUrl = getLpaSignatureXMLUrl();
		InputStream signatureInputStream = null;
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

		Document doc = null;
		try {
			byte[] lpaByte = this.lpa.getLpaBytes();
			if (lpaByte != null) {
				signatureInputStream = new ByteArrayInputStream(lpaByte);
			} else {
				signatureInputStream = this.lpa.getSignatureStream(lpaSignatureUrl);
			}
			doc = this.takeDocumentBuilder().parse(signatureInputStream);
		} catch (SAXException e) {
			setLoggerAndLpaValidErrorMessage(
					"O XML do arquivo da LPA está mal escrito.", e);
			return;
		} catch (IOException e) {
			setLoggerAndLpaValidErrorMessage(
					"Erro de entrada e saída do arquivo XML.", e);
			return;
		} catch (LpaException e) {
			setLoggerAndLpaValidErrorMessage(UNABLE_TO_CONNECT_TO_LPA, e);
			return;
		}

		NodeList nodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
				"Signature");
		if (nodeList.getLength() == 0) {
			Application.logger.log(Level.SEVERE, NO_SIGNATURE_FOUND);
			setLpaValidErrorMessage(NO_SIGNATURE_FOUND);
			return;
		}

		NodeList certList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
		String encodedCert = certList.item(0).getTextContent();
		byte[] decodedCert = Base64.decode(encodedCert);
		X509Certificate lpaCertificate = getCertificate(decodedCert);
		DOMValidateContext validateContext = new DOMValidateContext(lpaCertificate.getPublicKey(), nodeList.item(0));
		validateContext.setProperty("org.jcp.xml.dsig.secureValidation",
				Boolean.FALSE); /* workaround for ???? */

		URL urlToValidate = null;
		urlToValidate = getUrlToValidate(lpaSignatureUrl, urlToValidate);
		validateContext.setBaseURI(urlToValidate.toString());

		XMLSignature xmlSignature = null;
		boolean validity = false;
		try {
			xmlSignature = factory.unmarshalXMLSignature(validateContext);
			validity = xmlSignature.validate(validateContext);
			this.report.setLpaValid(validity);
			
			if(!validity) {
				setLpaValidErrorMessage("A LPA é invalida.");
			}
		} catch (MarshalException e) {
			setLoggerAndLpaValidErrorMessage(
					"Não foi possível decodificar a assinatura XMLDSig.", e);
        } catch (XMLSignatureException e) {
			setLoggerAndLpaValidErrorMessage(
					"O certificado utilizado está corretamente instalado no repositório do sistema.", e);
        }
	}

	/**
	 * Valida a LPA no formato ASN.1 de acordo com o tipo da LPA
	 * @param type O tipo da LPA
	 */
	private void validateASN1OfType(String type) {
	    Application application = this.signaturePolicyComponent.getApplication();
        String lpaUrl = application.getComponentParam(signaturePolicyComponent, "lpaUrlAsn1" + type);
        String lpaSignatureUrl = application.getComponentParam(signaturePolicyComponent,
                "lpaUrlAsn1Signature" + type);
        validateASN1(lpaUrl, lpaSignatureUrl);
    }

	/**
	 * Retorna a URL da LPA
	 * @param lpaSignatureUrl O caminho da assinatura da LPA
	 * @param urlToValidate A URL da LPA
	 * @return A URL da LPA
	 */
	private URL getUrlToValidate(String lpaSignatureUrl, URL urlToValidate) {
		try {
			urlToValidate = new URL(lpaSignatureUrl);
		} catch (MalformedURLException e1) {
			e1.printStackTrace();
		}
		return urlToValidate;
	}

	/**
	 * Adiciona a mensagem ao log de execução e adiciona o erro ao relatório
	 * @param logMessage A mensagem a ser escrita no log
	 * @param e A exceção que ocorreu
	 */
	private void setLoggerAndLpaValidErrorMessage(String logMessage, Exception e) {
		Application.logger.log(Level.SEVERE, logMessage, e);
		setLpaValidErrorMessage(logMessage);
	}

	/**
	 * Adiciona o erro ao relatório de validação
	 * @param errorMessage A mensagem de erro da validação da LPA
	 */
	private void setLpaValidErrorMessage(String errorMessage) {
		this.report.setLpaValid(false);
		this.report.setLpaErrorMessage(errorMessage);
	}

	/**
	 * Gera um objeto {@link DocumentBuilder}
	 * @return O objeto {@link DocumentBuilder} criado
	 */
	private DocumentBuilder takeDocumentBuilder() {
		DocumentBuilderFactory documentFactory = DocumentBuilderFactory
				.newInstance();
		documentFactory.setNamespaceAware(true);

		DocumentBuilder documentBuilder = null;
		try {
			documentBuilder = documentFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		}

		return documentBuilder;
	}

	/**
	 * Obtém a URL da assinatura da LPA utilizada
	 * @return URL da assinatura da LPA
	 */
	private String getLpaSignatureXMLUrl() {
		return this.signaturePolicyComponent.getApplication()
				.getComponentParam(signaturePolicyComponent,
						"lpaUrlXmlSignature");
	}

	/**
	 * Valida a LPA no formato ASN.1
	 */
	private void validateASN1(String lpaUrl, String lpaSignatureUrl) {
		reportDefaultInformations(this.report);

		try {
			/*Reutilizar bytes salvos na instância de Lpa ao invés de baixar novamente os dados*/
			byte[] sigBytes = this.lpa.getSignatureBytes();
			InputStream signatureInputStream;
			if (sigBytes != null) {
				signatureInputStream = new ByteArrayInputStream(sigBytes);
			} else {
				signatureInputStream = this.lpa.getSignatureStream(lpaSignatureUrl);
			}

			byte[] lpaBytes = this.lpa.getLpaBytes();
			InputStream lpaInputStream;
			if (lpaBytes != null) {
				lpaInputStream = new ByteArrayInputStream(lpaBytes);
			} else {
				lpaInputStream = this.lpa.getLpaStream(lpaUrl);
			}

			byte[] bytesOfsignature = Streams.readAll(signatureInputStream);
			CMSSignedData cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(
					Streams.readAll(lpaInputStream)), bytesOfsignature);
			Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();

			byte[] certificate = null;
			ASN1Sequence sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(bytesOfsignature);
			ASN1TaggedObject tagged = (ASN1TaggedObject) sequence.getObjectAt(1);
			if (tagged.getTagNo() == 0) {
				sequence = (ASN1Sequence) tagged.getObject();
				tagged = (ASN1TaggedObject) sequence.getObjectAt(3);
				if (tagged.getTagNo() == 0) {
					sequence = (ASN1Sequence) tagged.getObject();
					certificate = sequence.getEncoded();
				}
			}

			X509Certificate lpaCertificate = getCertificate(certificate);
			SignerInformationVerifier signerInfoVerifier = this.getSignerInformationVerifier(lpaCertificate);
			verify(signers, signerInfoVerifier);

		} catch (MalformedURLException e) {
			setLoggerAndLpaValidErrorMessage(MALFORMED_URL, e);
        } catch (CMSException e) {
			setLoggerAndLpaValidErrorMessage(INVALID_CMS, e);
        } catch (LpaException e) {
			setLoggerAndLpaValidErrorMessage(UNABLE_TO_CONNECT_TO_LPA, e);
        } catch (IOException e) {
			setLoggerAndLpaValidErrorMessage("Erro de Entrada/Saida", e);
        }
	}

	/**
	 * Verifica as informações de assinatura da LPA
	 * @param signers Os signatários desta assinatura
	 * @param signerInfoVerifier Estrutura que auxilia a verificação das informações do
	 *            signatário
	 */
	private void verify(Collection<SignerInformation> signers,
			SignerInformationVerifier signerInfoVerifier) {

		try {
			if (signers.iterator().next().verify(signerInfoVerifier)) {
				report.setLpaValid(true);
			} else {
				report.setLpaErrorMessage("Assinatura da LPA inválida.");
			}
		} catch (CMSException | NullPointerException e) {
			Application.logger.log(Level.SEVERE, INVALID_CMS, e);
			report.setLpaErrorMessage("Não foi possível verificar a validade da LPA.");
		}

	}

	/**
	 * Obtém o certificado utilizado para assinar a LPA
	 * @param lpaCertificate O certificado utilizado para assinar a LPA
	 * @return As informações do assinante
	 */
	private SignerInformationVerifier getSignerInformationVerifier(
			X509Certificate lpaCertificate) {
		JcaSimpleSignerInfoVerifierBuilder simpleSignerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
		if (lpaCertificate != null) {
			try {
				return simpleSignerInfoVerifierBuilder.build(lpaCertificate);
			} catch (OperatorCreationException e) {
				Application.logger
						.log(Level.SEVERE,
								"Não foi possível inicializar o verificador da assinatura.",
								e);
			}
		}
		return null;
	}

	/**
	 * Obtém o InputStream da assinatura da LPA
	 * @param lpaSignatureUrl URL da LPA
	 * @return O InputStream da assinatura da LPA
	 * @throws LpaException Exceção em caso de erro na busca pelo arquivo da LPA
	 */
	private InputStream getSignatureStream(String lpaSignatureUrl) throws LpaException {
		URL signatureUrl = null;
		InputStream inputStream = null;
		URLConnection urlConnection = null;
		try {
			signatureUrl = new URL(lpaSignatureUrl);
			urlConnection = signatureUrl.openConnection();
			inputStream = getInputStream(inputStream, urlConnection);
		} catch (MalformedURLException e) {
			Application.logger.log(Level.SEVERE, MALFORMED_URL, e);
		} catch (IOException ioException) {
			Application.logger.log(Level.SEVERE,
					"Erro na entrada ou saida do stream da assinatura",
					ioException);
		} catch (LpaException e) {
			report.setLpaErrorMessage(UNABLE_TO_CONNECT_TO_LPA);
			Application.logger.log(Level.SEVERE, UNABLE_TO_CONNECT_TO_LPA, e);
			throw new LpaException(UNABLE_TO_CONNECT_TO_LPA);
		}

		return inputStream;
	}

	/**
	 * Retorna o InputStream na conexão
	 * @param inputStream O stream da resposta da conexão
	 * @param urlConnection A conexão feita para ser feito o download da assinatura
	 * @return O stream da assinatura na conexão
	 * @throws LpaException Exceção em caso de erro na busca pelo arquivo da LPA
	 */
	private InputStream getInputStream(InputStream inputStream,
			URLConnection urlConnection) throws LpaException {
		if (urlConnection != null) {
			boolean retry = false;
			try {
				inputStream = urlConnection.getInputStream();
			} catch (IOException ioException) {
				retry = true;
			}
			if (retry) {
				try {
					inputStream = urlConnection.getInputStream();
				} catch (IOException ioException) {
					throw new LpaException(
							"Não foi possível acessar o conteúdo da página da Assinatura",
							ioException.getStackTrace());
				}
			}
		}
		return inputStream;
	}

	/**
	 * Retorna o certificado correspondente aos bytes
	 * @param certificate Os bytes do certificado
	 * @return O certificado correspondente
	 */
	private X509Certificate getCertificate(byte[] certificate) {
		if (certificate != null) {
			ByteArrayInputStream inputStream = new ByteArrayInputStream(certificate);
			try {
				CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
				return (X509Certificate) certificateFactory.generateCertificate(inputStream);
			} catch (CertificateException e) {
				Application.logger.log(Level.SEVERE,
						"Erro com o certificado utilizado na assinatura da lpa", e);
			}
		}
		return null;
	}

	/**
	 * Inicializa os valores do relatório com valores padrão
	 * @param report O relatório de validação da LPA
	 */
	private void reportDefaultInformations(Report report) {
		report.setLpaVersion("2");
		report.setOnline(true);
		SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss z");
		Date nextUpdate = this.lpa.getNextUpdate();
		if (nextUpdate != null) {
			report.setPeriod(formatter.format(nextUpdate));
		} else {
			report.setPeriod(UNABLE_TO_CONNECT_TO_LPA);
		}
	}

	/**
	 * Verifica se a LPA estava expirada no momento da assinatura
	 * @param report O relatório de validação da LPA
	 */
	public void verifyLpaExpirationDate(Report report) {
		List<SignatureReport> signatures = report.getSignatures();

		if (!signatures.isEmpty()) {
			List<TimeStampReport> stamps = signatures.get(0).getStamps();
			Date timeRef = new Date();

			if (!stamps.isEmpty()) {
				String timeReference = stamps.get(0).getTimeReference();
				SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss z");
				try {
					if (timeReference != null) {
						timeRef = dateFormat.parse(timeReference);
					}
				} catch (ParseException e) {
					/* Check the date's format inside TimeStampReport#setTimeReference(). */
					e.printStackTrace();
				}
			}
			Date nextUpdate = this.lpa.getNextUpdate();
			if (nextUpdate != null) {
				if (timeRef.after(nextUpdate)) {
					report.setLpaExpired(TRUE);
				} else {
					report.setLpaExpired(FALSE);
				}
			}
		}
	}

}
