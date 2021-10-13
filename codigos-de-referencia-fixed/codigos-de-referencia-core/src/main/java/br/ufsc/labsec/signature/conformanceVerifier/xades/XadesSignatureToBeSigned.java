package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.net.URI;
import java.security.Signature;

import javax.xml.crypto.dsig.XMLObject;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureModeXAdES;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.NodeOperationException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;

/**
 * Esta classe representa uma assinatura que será assinada. Seu modo será
 * <b>sempre COUNTERSIGNED</b>.
 * Estende {@link XadesContentToBeSigned}
 */
public class XadesSignatureToBeSigned extends XadesContentToBeSigned
{

	/**
	 * Assinatura XAdES
	 */
	protected XadesSignature signature;

	/**
	 * Essa classe representa uma assinatura que será assinada. Seu modo será
	 * <b>sempre COUNTERSIGNED</b>
	 * 
	 * @param signature {@link Signature} que será assinada
	 * @throws NodeOperationException
	 */
	public XadesSignatureToBeSigned(XadesSignature signature) throws NodeOperationException
	{
		super(SignatureModeXAdES.COUNTERSIGNED);
		this.signature = signature;
		this.setDocument(this.signature.getXml());
	}

	/**
	 * Contra-assinaturas não precisam de {@link URI} base.
	 */
	@Override
	URI getBaseUri()
	{
		return null;
	}

	/**
	 * A {@link URI} que a referência desse conteúdo deve apontar é o valor da
	 * assinatura que será assinada.
	 * @return A URI do conteúdo assinado
	 */
	@Override
	protected String getUri(URI baseUri)
	{
		String signatureId = signature.getSignatureValueAttribute();
		return "#" + signatureId;
	}

	/**
	 * Retorna o nodo que contém a assinatura
	 * @return O nodo que contém a assinatura
	 * @throws SignatureModeException
	 */
	@Override
	public Element getEnvelopNode() throws SignatureModeException
	{
		if(this.nodeToEnvelop == null){
			this.setEnvelopeNode(this.createCounterSignatureNode());
		}
		return this.nodeToEnvelop;
	}

	/**
	 * Contra-assinaturas não precisam de nenhum {@link XMLObject} especifico.
	 */
	@Override
	public XMLObject getObject(String id)
	{
		return null;
	}

	/**
	 * Gera o nodo da contra assinatura
	 * @return O nodo da contra assinatura
	 */
	protected Element createCounterSignatureNode()
	{
		Element signature = this.signature.getSignatureElement();
		Document owerDocument = signature.getOwnerDocument();
		Element qualifyingProperties =
				(Element) signature.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "QualifyingProperties")
						.item(0);
		Element unsignedProperties =
				(Element) signature.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "UnsignedProperties")
						.item(0);
		if(unsignedProperties == null){
			unsignedProperties =
					owerDocument.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:UnsignedProperties");
			qualifyingProperties.appendChild(unsignedProperties);
		}
		Element unsignedSignatureProperties =
				(Element) unsignedProperties.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						"UnsignedSignatureProperties").item(0);
		if(unsignedSignatureProperties == null){
			unsignedSignatureProperties =
					owerDocument
							.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:UnsignedSignatureProperties");
			unsignedProperties.appendChild(unsignedSignatureProperties);
		}
		Element counterSignature =
				owerDocument.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CounterSignature");
		Node counterSignatureNode = unsignedSignatureProperties.appendChild(counterSignature);
		return (Element) counterSignatureNode;
	}
}
