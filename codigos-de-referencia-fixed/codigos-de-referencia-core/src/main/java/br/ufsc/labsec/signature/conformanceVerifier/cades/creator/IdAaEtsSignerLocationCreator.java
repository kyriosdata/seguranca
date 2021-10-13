package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.util.ArrayList;
import java.util.List;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSignerLocation;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo IdAaEtsSignerLocationCreator
 */
public class IdAaEtsSignerLocationCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdAaEtsSignerLocationCreator(CadesAttributeIncluder cadesAttributeIncluder) {
		super(cadesAttributeIncluder);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 */
	@Override
	public SignatureAttribute getAttribute() throws SignatureAttributeException
	{
	String city = null, 
			stateOrProvince = null, 
			postalCode = null, 
			countryName = null;
	
	List<String> postalCodeList = null;
				
	city = cadesAttributeIncluder.getComponent().getApplication().getComponentParam(cadesAttributeIncluder.getComponent(), "city");
	stateOrProvince = cadesAttributeIncluder.getComponent().getApplication().getComponentParam(cadesAttributeIncluder.getComponent(), "stateOrProvince");
	postalCode = cadesAttributeIncluder.getComponent().getApplication().getComponentParam(cadesAttributeIncluder.getComponent(), "postalCode");
	countryName = cadesAttributeIncluder.getComponent().getApplication().getComponentParam(cadesAttributeIncluder.getComponent(), "countryName");

	if(postalCode != null) {
		postalCodeList = new ArrayList<String>();
		postalCodeList.add(postalCode);
	}
	
		return new IdAaEtsSignerLocation(countryName, city, postalCodeList);
	}

}
