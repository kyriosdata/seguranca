package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.security.cert.X509CRL;
import java.util.List;

import javax.xml.crypto.dsig.DigestMethod;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteRevocationRefs;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo CompleteRevRefs
 */
public class CompleteRevocationRefsCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public CompleteRevocationRefsCreator(AbstractXadesSigner xadesSigner) {
		super(xadesSigner);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 * @throws SignatureAttributeException Exceção caso ocorra algum erro durante
	 * a construção do objeto
	 */
	@Override
	public SignatureAttribute getAttribute() throws SignatureAttributeException {
		String algorithm = this.xadesSigner.getComponent().getApplication().getComponentParam(
				this.xadesSigner.getComponent(), "algorithmOid");
		List<X509CRL> crls = this.xadesSigner.getCRLs();

		CompleteRevocationRefs completeRevocationRefs = new CompleteRevocationRefs(crls, algorithm);

		return completeRevocationRefs;
	}

}
