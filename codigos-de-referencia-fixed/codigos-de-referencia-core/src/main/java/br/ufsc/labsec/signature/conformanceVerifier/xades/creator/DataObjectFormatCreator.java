package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.FileToBeSigned;
import br.ufsc.labsec.signature.conformanceVerifier.xades.MimeTypesMap;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo DataObjectFormat
 */
public class DataObjectFormatCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public DataObjectFormatCreator(AbstractXadesSigner xadesSigner) {
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
		
		DataObjectFormat dataObjectFormat = null;
		try {
			
			FileToBeSigned contentToBeSigned = (FileToBeSigned) xadesSigner.getContentToBeSigned();
			
			dataObjectFormat = new DataObjectFormat(this.generateNewReferenceId(), null, null, 
					MimeTypesMap.getInstance().getContentType(contentToBeSigned.getFileToBeSigned()), null);
			dataObjectFormat.setContent(contentToBeSigned);
		} catch (SignatureAttributeException e) {
			throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + DataObjectFormat.IDENTIFIER, e);
		}
		
		return dataObjectFormat;
		
	}

	/**
	 * Cria um identificador de referência
	 * @return O identificador de referência gerado
	 */
	private String generateNewReferenceId() {
		long idNumber = (long) (Math.random() * 1000000 * 1000000 * 1000000) + 1;
		return "id" + idNumber;
	}
	
}
