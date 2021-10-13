package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CoSigner;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.signer.SignerType;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

/**
 * Esta classe adiciona uma co-assinatura CAdES a um documento.
 * Estende {@link AbstractCadesSigner} e implementa {@link CoSigner}.
 */
public class CadesCoSigner extends AbstractCadesSigner implements CoSigner {

	/**
	 * Construtor
	 * @param cadesSignature Componente de assinatura CAdES
	 */
	public CadesCoSigner(CadesSignatureComponent cadesSignature) {
		super(cadesSignature);
	}

	/**
	 * Verifica se o documento pode ser co-assinado
	 * @param signatureAdress O endereço do arquivo de assinatura
	 * @return Indica se o documento pode ser co-assinado
	 */
	@Override
	public boolean canCoSign(String signatureAdress) {

		boolean ret = false;
		byte[] signatureBytes = getFileBytes(signatureAdress);
		try {
			new CadesSignatureContainer(signatureBytes);
			ret = true;
		} catch (Exception e) {
		}

		return ret;
	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target O endereço do arquivo de assinatura
	 * @param signedContent O endereço do conteúdo assinado
	 * @param signaturePolicy O OID da política usada
	 */
	@Override
	public void selectTarget(String target, String signedContent,
			String signaturePolicy) {
		byte[] signatureBytes = getFileBytes(target);
		byte[] signedContentBytes = null;
		try {
			this.attributeIncluder.setSelectedAttributes(new ArrayList<String>());
			this.attributeIncluder
					.setSignatureContainer(new CadesSignatureContainer(
							signatureBytes));
			if (this.attributeIncluder.getSignatureContainer()
					.hasDetachedContent()) {
				if (signedContent != null && !signedContent.isEmpty()) {
					signedContentBytes = getFileBytes(signedContent);
					this.attributeIncluder.getSignatureContainer()
							.setSignedContent(signedContentBytes);

					CadesContentToBeSigned contentToBeSigned = new CadesContentToBeSigned(
							signedContentBytes, this.attributeIncluder
									.getSignatureContainer().getSignatureAt(0).getMode());
					this.attributeIncluder
							.setContentToBeSigned(contentToBeSigned);
				}
			}
		} catch (CadesSignatureException e1) {
			Application.logger.log(Level.SEVERE, e1.getMessage(), e1);
		} catch (EncodingException e1) {
			Application.logger.log(Level.SEVERE, e1.getMessage(), e1);
		} catch (PbadException e) {
			Application.logger.log(Level.SEVERE,
					"Erro ao ler o conteudo assinado", e);
		}

		this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.setActualPolicy(signaturePolicy, null, AdESType.CAdES);
		this.attributeIncluder.getSelectedAttributes().addAll(
				this.getMandatedSignedAttributeList());
		this.attributeIncluder.getSelectedAttributes().addAll(
				this.getMandatedUnsignedAttributeList());

	}

	/**
	 * Realiza a co-assinatura
	 * @return Indica se a co-assinatura foi realizada com sucesso
	 */
	@Override
	protected Signature sign(
			SignatureContainerGenerator signatureContainerGenerator) {
		CadesCoSignatureGenerator coSignatureGenerator = (CadesCoSignatureGenerator) signatureContainerGenerator;
		return coSignatureGenerator.coSign();
	}

	/**
	 * Realiza a co-assinatura
	 * @return Indica se a co-assinatura foi realizada com sucesso
	 */
	@Override
	public boolean coSign() {
		boolean error = false;
		List<String> unsignedAttributesList = new ArrayList<>();

		String policyId = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getPolicyId();
		byte[] policyHash = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getSignPolicyHash();
		String policyHashAlgorithm = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getHashAlgorithmId();

		String policyURL = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getURL(AdESType.CAdES);

		IdAaEtsSigPolicyId sigPolicyId = new IdAaEtsSigPolicyId(policyId,
				policyHashAlgorithm, policyHash, policyURL);
		this.signatureContainerGenerator = new CadesCoSignatureGenerator(
				this.attributeIncluder.getSignatureContainer(), sigPolicyId,
				this.attributeIncluder.getCadesSignature());
		this.signatureContainerGenerator.addContentToBeSigned(this.attributeIncluder.getContentToBeSigned());
		return doSign(error, unsignedAttributesList,
				signatureContainerGenerator);
	}

	@Override
	public SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policyOid) {
		// TODO
		return null;
	}
}
