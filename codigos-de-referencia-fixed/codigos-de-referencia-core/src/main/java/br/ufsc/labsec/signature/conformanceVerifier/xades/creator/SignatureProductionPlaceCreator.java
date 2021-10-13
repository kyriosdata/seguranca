package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignatureProductionPlace;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo SignatureProductionPlace
 */
public class SignatureProductionPlaceCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public SignatureProductionPlaceCreator(AbstractXadesSigner xadesSigner) {
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
		
		String city = null, 
				stateOrProvince = null, 
				postalCode = null, 
				countryName = null;
					
		city = xadesSigner.getComponent().getApplication().getComponentParam(xadesSigner.getComponent(), "city");
		stateOrProvince = xadesSigner.getComponent().getApplication().getComponentParam(xadesSigner.getComponent(), "stateOrProvince");
		postalCode = xadesSigner.getComponent().getApplication().getComponentParam(xadesSigner.getComponent(), "postalCode");
		countryName = xadesSigner.getComponent().getApplication().getComponentParam(xadesSigner.getComponent(), "countryName");
	
		if(city.equals("")) city = null;
		if(stateOrProvince.equals("")) stateOrProvince = null;
		if(postalCode.equals("")) postalCode = null;
		if(countryName.equals("")) countryName = null;
		
		SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace(city, stateOrProvince, postalCode, countryName);

		return signatureProductionPlace;
		
	}


}
