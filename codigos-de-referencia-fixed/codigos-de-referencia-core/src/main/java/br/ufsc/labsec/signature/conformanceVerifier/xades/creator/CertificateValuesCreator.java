package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.security.cert.X509Certificate;
import java.util.List;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertValuesException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertificationPathException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo CertValues
 */
public class CertificateValuesCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public CertificateValuesCreator(AbstractXadesSigner xadesSigner) {
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
		CertificateValues certValues;
		try {
			
			List<X509Certificate> signCertPath = xadesSigner.getCertificateReferences();
			
			certValues = new CertificateValues(xadesSigner.getAttributeFactory().getSignerCertificate(), signCertPath);
		} catch (CertValuesException | CertificationPathException e) {
			throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + CertificateValues.IDENTIFIER, e);
		}
		return certValues;
	}

}
