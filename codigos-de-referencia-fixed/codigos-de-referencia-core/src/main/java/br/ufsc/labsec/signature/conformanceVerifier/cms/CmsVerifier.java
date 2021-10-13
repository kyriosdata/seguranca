package br.ufsc.labsec.signature.conformanceVerifier.cms;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.Constants;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.SignatureNotICPBrException;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report.ReportType;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.VerificationException;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe implementa os métodos para verificação de uma assinatura CMS.
 * Implementa {@link Verifier}
 */
public class CmsVerifier implements Verifier {

	/**
	 * Contêiner de assinatura CMS
	 */
	private CmsSignatureContainer signatureContainer;
	/**
	 * Assinatura CMS a ser verificada
	 */
	private CmsSignature selectedSignature;
	/**
	 * Componente de assinatura CMS
	 */
	private CmsSignatureComponent cmsSignatureComponent;
	/**
	 * Resultados da verificação do documento
	 */
	private Report report;

	/**
	 * Construtor
	 * @param cmsSignatureComponent Componente de assinatura CMS
	 */
	public CmsVerifier(CmsSignatureComponent cmsSignatureComponent) {
		this.cmsSignatureComponent = cmsSignatureComponent;
	}

	/**
	 * Inicializa os bytes do documento CMS assinado
	 * @param target Os bytes do documento CMS assinado
	 * @param signedContent Os bytes do conteúdo assinado no documento
	 * @throws VerificationException Exceção caso os bytes não sejam uma assinatura válida
	 */
	@Override
	public void selectTarget(byte[] target, byte[] signedContent) throws VerificationException {

		byte[] signatureBytes = target;
		this.signatureContainer = new CmsSignatureContainer(signatureBytes, this.cmsSignatureComponent);

		byte[] signedContentBytes = null;
		try {
			if (this.signatureContainer.hasDetachedContent()) {
				if (signedContent != null) {
					signedContentBytes = signedContent;
					try {
						this.signatureContainer.setSignedContent(signedContentBytes);
					} catch (PbadException e) {
						Application.logger.log(Level.SEVERE, "Erro ao ler o conteudo assinado", e);
						throw new VerificationException(e);
					}
				}
			}
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, "Erro ao ler a assinatura", e);
			throw new VerificationException(e);
		}

	}

	/**
	 * Retorna as assinaturas no documento
	 * @return As assinaturas no documento
	 */
	@Override
	public List<String> getSignaturesAvailable() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Seleciona uma das assinaturas
	 * @param signatureSelected Identificador das assinatura
	 */
	@Override
	public void selectSignature(String signatureSelected) {
		// TODO Auto-generated method stub
	}

	/**
	 * Retorna o relatório da validação de uma assinatura
	 * @return O relatório da validação de uma assinatura
	 */
	@Override
	public SignatureReport getValidationResult() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Retorna os atributos que podem ser inseridos na assinatura selecionada
	 * @return Os atributos que podem ser inseridos na assinatura
	 */
	@Override
	public List<String> getAvailableAttributes() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Adiciona um atributo
	 * @param attribute Nome do atributo que deve ser inserido
	 * @return Indica se a inserção foi bem sucedida
	 */
	@Override
	public boolean addAttribute(String attribute) {
		// TODO Auto-generated method stub
		return false;
	}

	/**
	 * Limpa as informações do verificador
	 * @return Indica se a limpeza foi bem sucedida
	 */
	@Override
	public boolean clear() {
		this.selectedSignature = null;
		this.signatureContainer = null;
		this.report = null;
		return true;
	}

	/**
	 * Cria um objeto {@link Report} com as informações da verificação
	 * @param target O documento a ser verificado
	 * @param signedContent O conteúdo assinado do documento CMS
	 * @param type Tipo de relatório desejado
	 * @return O relatório da verificação
	 * @throws VerificationException Exceção caso haja algum problema na verificação
	 */
	@Override
	public Report report(byte[] target, byte[] signedContent, ReportType type) throws VerificationException {

		Security.addProvider(new BouncyCastleProvider());

		this.createReport();

		selectTarget(target, signedContent);
		if (this.signatureContainer != null) {
			for (CmsSignature sign : this.signatureContainer.getSignatures()) {
				this.report.addSignatureReport(sign.validate());
			}
		}

		return this.report;

	}

	/**
	 * Verifica se o documento é uma assinatura CMS
	 * @param filePath Diretório do arquivo a ser verificado
	 * @return Indica se o arquivo é uma assinatura CMS
	 */
	@Override
	public boolean isSignature(String filePath) {
		// TODO Auto-generated method stub
		return false;
	}

	/**
	 * Verifica se a assinatura possui conteúdo destacado
	 * @return Indica se a assinatura possui conteúdo destacado
	 */
	@Override
	public boolean needSignedContent() {

		try {
			return this.signatureContainer.hasDetachedContent();
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
		}

		return false;

	}

	/**
	 * Retorna uma lista de atributos obrigatórios
	 * @return Uma lista de atributos obrigatórios
	 */
	@Override
	public List<String> getMandatedAttributes() {
		AttributeTable attr = this.selectedSignature.getSignerInfo().getSignedAttributes();
		if (attr != null) {
			return this.selectedSignature.getAttributeList().subList(0, attr.size());
		}
		return null;
	}

	/**
	 * Verifica se o documento assinado é uma assinatura CMS
	 * @param sig Os bytes do documento assinado
	 * @param detached Os bytes do arquivo destacado
	 * @return Indica se o documento assinado é uma assinatura CMS
	 * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita com um certificado ICP-Brasil
	 */
	@Override
	public boolean supports(byte[] sig, byte[] detached) throws SignatureNotICPBrException {
		try {
			this.selectTarget(sig, detached);
		} catch (VerificationException e) {
			return false;
		}
		List<CmsSignature> signatures = this.signatureContainer.getSignatures();

		if (!signatures.isEmpty()) {
			boolean validSignature = true;
			Iterator<CmsSignature> itSign = this.signatureContainer.getSignatures().iterator();
			while (itSign.hasNext() && validSignature) {
                validSignature = this.validSignature(itSign.next());
            }
			return validSignature;
		}
		return false;
	}

	/**
	 * Verifica se a assinatura foi feita com um certificado ICP-Brasil e se é uma assinatura CMS
	 * @param s A assinatura a ser verificada
	 * @return Indica se a assinatura é uma assinatura CMS e ICP-Brasil
	 * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita com um certificado ICP-Brasil
	 */
    private boolean validSignature(CmsSignature s) throws SignatureNotICPBrException {
		boolean noPolicy = false;
		boolean isICPBR = false;

		X509Certificate c = s.getSigningCertificate();

		isICPBR = this.checkCertPath(c);
		if (!isICPBR) {
			throw new SignatureNotICPBrException("Signer certificate is not from ICP-Brasil.");
		}
		noPolicy = !s.getAttributeList().contains(
				PKCSObjectIdentifiers.id_aa_ets_sigPolicyId.toString());

        return isICPBR && noPolicy;
    }

	/**
	 * Inicializa um objeto {@link Report}
	 */
	private void createReport() {

		this.report = new Report();
		report.setSoftwareName(Constants.VERIFICADOR_NAME);
		report.setSoftwareVersion(Constants.SOFTWARE_VERSION);
		report.setVerificationDate(new Date());
		report.setSourceOfDate("Offline");

	}

	/**
	 * Retorna o contêiner de assinatura CMS
	 * @return O contêiner de assinatura CMS
	 */
	public CmsSignatureContainer getSignatureContainer() {
		return this.signatureContainer;
	}

	/**
	 * Verifica se é possível criar o caminho de certificação da assinatura
	 * @param certificate Certificado utilizado na assinatura
	 * @return Indica se o caminho de certificação foi criado com sucesso
	 */
	private boolean checkCertPath(X509Certificate certificate) {
		Set<TrustAnchor> trustAnchors = this.cmsSignatureComponent.trustAnchorInterface.getTrustAnchorSet();
		Time timeReference = new Time(SystemTime.getSystemTime());

		CertPath certpath = this.cmsSignatureComponent.certificatePathValidation.generateCertPathNoSave(certificate, trustAnchors, timeReference);

		return certpath != null;
	}

}
