package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.util.logging.Level;

import org.bouncycastle.cms.SignerInformation;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdCounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureContainer;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe adiciona uma contra-assinatura CAdES.
 * Estende {@link SignatureContainerGenerator}.
 */

public class CounterSignatureGenerator extends SignatureContainerGenerator {

	/**
	 * Construtor
	 * @param signaturePolicyIdentifier O identificador da política de assinatura a ser utilizada
	 * @param cadesSignature Componente de assinatura XAdES
	 */
	public CounterSignatureGenerator(
			IdAaEtsSigPolicyId signaturePolicyIdentifier,
			CadesSignatureComponent cadesSignature) {
		super(signaturePolicyIdentifier, cadesSignature);
	}

	/**
	 * Gera a contra assinatura
	 * @return {@link Signature} que contém a assinatura gerada
	 * @throws CadesSignatureException exceção em caso de erro durante a geração da assinatura
	 */
	public Signature counterSign() throws CadesSignatureException {
		Signature signature = null;
		try {
			signature = super.sign().getSignatureAt(0);
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
			return null;
		}
		Signature resultingSignature = null;

		resultingSignature = this
				.addCadesCounterSignature((CadesSignature) signature);

		return resultingSignature;
	}

	/**
	 * Adiciona a contra assinatura criada no padrão CAdES a um CMSSignedData
	 * @return {@link Signature} que contém a assinatura gerada
	 */
	protected Signature addCadesCounterSignature(
			CadesSignature cadesCounterSignature) {
		SignerInformation counterSignerInformation = cadesCounterSignature
				.getSignerInformation();
		CadesSignatureToBeSigned contentToBeSigned = (CadesSignatureToBeSigned) super
				.getContentsToBeSigned().get(0);
		CadesSignatureInformation cadesSignature = contentToBeSigned
				.getSignatureToBeCounterSigned();
		IdCounterSignature counterSignature = new IdCounterSignature(
				counterSignerInformation, cadesSignature);
		cadesSignature.addCounterSignature(counterSignature);

		return counterSignature;
	}
}
