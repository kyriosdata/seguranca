package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TimeStampResponse;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.AttributeCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.AttributeRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SigAndRefsTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo SigAndRefsTimeStamp
 */
public class SigAndRefsTimeStampCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public SigAndRefsTimeStampCreator(AbstractXadesSigner xadesSigner) {
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

		SignatureAttribute attribute = null;
		
		try { 
			
			String algorithmOid = xadesSigner.getComponent().getApplication().getComponentParam(xadesSigner.getComponent(), "algorithmOid");
			String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmOid);
			List<String> atts = xadesSigner.getSignature().getAttributeList();
			
			if(!atts.contains(CompleteCertificateRefs.IDENTIFIER)) {
				Creator creator = new CompleteCertificateRefsCreator(xadesSigner);
				xadesSigner.getSignature().addUnsignedAttribute(creator.getAttribute());
				Application.logger.log(Level.FINE, "O attributo " + SigAndRefsTimeStamp.IDENTIFIER + " necessita do attributo " +
						CompleteCertificateRefs.IDENTIFIER + "para sua criação, esta atributo foi criado.");
			}
			
			if(!atts.contains(CompleteRevocationRefs.IDENTIFIER)) {
				Creator creator = new CompleteRevocationRefsCreator(xadesSigner);
				xadesSigner.getSignature().addUnsignedAttribute(creator.getAttribute());
				Application.logger.log(Level.FINE, "O attributo " + SigAndRefsTimeStamp.IDENTIFIER + " necessita do attributo " +
						CompleteRevocationRefs.IDENTIFIER + "para sua criação, esta atributo foi criado.");
			}
			
			if(!atts.contains(SignatureTimeStamp.IDENTIFIER)) {
				Creator creator = new SignatureTimeStampCreator(xadesSigner);
				xadesSigner.getSignature().addUnsignedAttribute(creator.getAttribute());
				Application.logger.log(Level.FINE, "O attributo " + SigAndRefsTimeStamp.IDENTIFIER + " necessita do attributo " +
						SignatureTimeStamp.IDENTIFIER + "para sua criação, esta atributo foi criado.");
			}
			
			if(atts.contains(AttributeCertificateRefs.IDENTIFIER)) {
				if(!atts.contains(AttributeRevocationRefs.IDENTIFIER)) {
					//Creator creator = new SignatureTimeStampCreator(xadesSigner);
					//TODO não existe ainda
					//xadesSigner.getSignature().getSignatureAt(0).addUnsignedAttribute(creator.getAttribute());
					Application.logger.log(Level.FINE, "O attributo " + SigAndRefsTimeStamp.IDENTIFIER + ", "
							+ "quando utilizado com o attributo " + AttributeCertificateRefs.IDENTIFIER + ""
									+ " necessita do attributo " +
									AttributeRevocationRefs.IDENTIFIER + "para sua criação, esta atributo foi criado.");
				}
			}
			
			byte[] digest = xadesSigner.getSignature().getSigAndRefsHashValue(algorithm);
			byte[] timeStamp = xadesSigner.getComponent().timeStamp.getTimeStamp(digest);
			
			TimeStampResponse response = new TimeStampResponse(timeStamp);
			
			byte[] toAddAttribute = response.getTimeStampToken().toCMSSignedData().toASN1Structure().getEncoded();
			
			List<String> attributes = xadesSigner.getUnsignedAttributes();
			List<String> cadesAttributes = new ArrayList<>();
			
			for (String att : attributes) {
				String a = super.getCadesAttributeName(att);
				if(a != null)
					cadesAttributes.add(super.getCadesAttributeName(att));
			}
		
			
			byte[] withAttributes = xadesSigner.getComponent().timeStampAttributeIncluder.addAttributesTimeStamp(toAddAttribute, cadesAttributes);
			
			attribute = new SigAndRefsTimeStamp(ContentInfo.getInstance((ASN1Sequence) ASN1Sequence.fromByteArray(withAttributes)));
			
			
		} catch (Exception e) {
			throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + SigAndRefsTimeStamp.IDENTIFIER, e);
		}	
		
		
		
		return attribute;
		
	}

}
