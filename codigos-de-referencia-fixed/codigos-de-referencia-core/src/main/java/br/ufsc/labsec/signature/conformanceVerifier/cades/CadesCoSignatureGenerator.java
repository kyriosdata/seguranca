package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;


/**
 * Esta classe adiciona uma co-assinatura a um contêiner de assinatura CAdES.
 * Estende {@link SignatureContainerGenerator}.
 */

public class CadesCoSignatureGenerator extends SignatureContainerGenerator
{

	/**
	 * Contêiner de assinatura CAdES
	 */
	protected CadesSignatureContainer signatureContainer;

	/**
	 * Construtor
	 * @param signatureContainer Contêiner ao qual a co-assinatura será adicionada
	 * @param signaturePolicyIdentifier Identificador da política de assinatura que irá realizar a co-assinatura
	 */
	public CadesCoSignatureGenerator(CadesSignatureContainer signatureContainer,
			IdAaEtsSigPolicyId signaturePolicyIdentifier, CadesSignatureComponent cadesSignature)
	{
		super(signaturePolicyIdentifier, cadesSignature);
		this.signatureContainer = signatureContainer;
	}

	/**
	 * Adiciona uma co-assinatura ao contêiner
	 * ATENÇÃO: Se o contêiner for ATTACHED não DEVE ser utilizado o método: addContentToBeSigned(ContentToBeSigned
	 * content)
	 * @return A assinatura adicionada
	 */
	public Signature coSign()
	{
		CadesSignature cadesSignature = null;
		try {
			if(this.signatureContainer.hasDetachedContent()){
				byte[] signedContent = this.signatureContainer.getSignedContent();
				CadesContentToBeSigned cadesContentToBeSigned =
						new CadesContentToBeSigned(signedContent, SignatureModeCAdES.ATTACHED);
				this.contentsToBeSigned.clear();
				this.addContentToBeSigned(cadesContentToBeSigned);
				cadesSignature = (CadesSignature) super.sign().getSignatureAt(0);
				this.signatureContainer.addSignature(cadesSignature);
			}
		} catch (EncodingException | CadesSignatureException e) {
			Application.logger.log(Level.SEVERE,e.getMessage(),e);
		}
		return cadesSignature;
	}
}