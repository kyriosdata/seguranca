/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.exceptions.VerificationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XadesSignatureContainerException;
import org.xml.sax.SAXException;

/**
 * Esta classe representa um contêiner de assinaturas XAdES.
 * Implementa {@link SignatureContainer}.
 */
public class XadesSignatureContainer implements SignatureContainer {

	/**
	 * O documento assinado
	 */
	protected Document xml;
	/**
	 * O conteúdo assinado
	 */
	private byte[] content;

	/**
	 * Constrói um contêiner de assinaturas a partir de um file. Esse file deve
	 * ser um arquivo xml, que pode conter várias assinaturas.
	 * 
	 * @param signatureContainer O arquivo XML que representa uma ou mais assinaturas
	 * 
	 * @throws XadesSignatureContainerException Exceção em caso de erro na criação do contêiner
	 */
	public XadesSignatureContainer(File signatureContainer)
			throws XadesSignatureContainerException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
			Document document = builder.parse(signatureContainer);
			this.xml = document;
		} catch (Exception e) {
			throw new XadesSignatureContainerException(e);
		}
	}

	/**
	 * Constrói um contêiner de assinaturas a partir de um stream. Esse stream
	 * deve ser um arquivo xml, que pode conter várias assinaturas.
	 * 
	 * @param signatureContainer O arquivo XML que representa uma ou mais assinaturas
	 * 
	 * @throws XadesSignatureContainerException Exceção em caso de erro na criação do contêiner
	 */
	public XadesSignatureContainer(InputStream signatureContainer)
			throws XadesSignatureContainerException, VerificationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
			Document document = builder.parse(signatureContainer);
			this.xml = document;
		} catch (ParserConfigurationException e) {
			Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar a assinatura na criação do " +
					"DocumentBuilderFactory no XadesSignatureContainer.", e);
			throw new XadesSignatureContainerException(e);
		} catch (SAXException | IOException e) {
			Application.loggerInfo.log(Level.WARNING, "Não foi possível abrir a assinatura como um org.w3c.dom.Document.");
			throw new VerificationException(e);
		}
	}

	/**
	 * Constrói um contêiner de assinaturas a partir de uma representação DOM de
	 * um documento XML que já foi trabalhado pela classe
	 * {@link ContainerGenerator}.
	 * 
	 * @param signatures A representação DOM de um documento XML que representa uma ou
	 *            mais assinaturas.
	 */
	public XadesSignatureContainer(Document signatures) {
		this.xml = signatures;
	}

	/**
	 * Constrói um contêiner de assinaturas a partir de um array de bytes de um arquivo XML
	 * @param target Os bytes do arquivo XML
	 * @throws XadesSignatureContainerException Exceção em caso de erro na criação do contêiner
	 * @throws VerificationException
	 */
	public XadesSignatureContainer(byte[] target)
			throws XadesSignatureContainerException, VerificationException {
		this(new ByteArrayInputStream(target));
	}

	/**
	 * Retorna a assinatura no índice dado
	 * @param index O índice da assinatura
	 * @return A assinatura do índice dado
	 */
	public XadesSignature getSignatureAt(int index) {
		XadesSignature xmlSignature = null;
		NodeList signatureList = this.xml.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XMLDSIG_NS, "Signature");
		if (signatureList.getLength() == 0) {
			signatureList = this.xml.getElementsByTagName("Signature");
		}
		/*
		 * Algoritmo para contar apenas as assinaturas e desconciderar as
		 * contra-assinaturas
		 */
		int sum = 0;
		if (signatureList.getLength() > 0) {
			Set<Node> nodeSet = new HashSet<Node>();
			boolean found = false;
			int i = 0;
			while (!found && i < signatureList.getLength()) {
				/*
				 * É verificado se a assinatura corrente já foi adicionada ao
				 * conjunto. Caso já, simplesmente é passado para o próximo item
				 * da lista.
				 */
				if (nodeSet.add(signatureList.item(i))) {
					sum++;
					if (sum == index + 1) {
						Element signatureElement = (Element) signatureList
								.item(i);
						xmlSignature = new XadesSignature(this.xml,
								signatureElement, this);
						found = true;
					}
					/*
					 * Quando é possível inferir que as assinaturas são
					 * contra-assinaturas então elas são adicionadas ao conjunto
					 * sem serem contabilizadas.
					 */
					Element signatureElement = (Element) signatureList.item(i);
					NodeList counterSignatureList = signatureElement
							.getElementsByTagName("ds:Signature");
					for (int j = 0; j < counterSignatureList.getLength(); j++)
						nodeSet.add(counterSignatureList.item(j));
				}
				i++;
			}
		}
		return xmlSignature;
	}

	/**
	 * Retorna a quantidade de nodos de assinatura no arquivo
	 * @return A quantidade de nodos de assinatura no arquivo
	 */
	public int getSignatureNodesCount() {
		NodeList signatureList = this.xml.getElementsByTagName("ds:Signature");
		if (signatureList.getLength() == 0) {
			signatureList = this.xml.getElementsByTagName("Signature");
		}

		return signatureList.getLength();
	}

	/**
	 * Retorna a quantidade de assinaturas no arquivo, desconsiderando contra-assinaturas
	 * @return A quantidade de assinaturas no arquivo
	 */
	public int getSignatureCount() {
		/*
		 * Não é possível diferenciar assinaturas de contra-assinaturas com essa
		 * função.
		 */
		NodeList signatureList = this.xml.getElementsByTagName("ds:Signature");
		if (signatureList.getLength() == 0) {
			signatureList = this.xml.getElementsByTagName("Signature");
		}

		/*
		 * Algoritmo para contar apenas as assinaturas e desconciderar as
		 * contra-assinaturas
		 */
		int sum = 0;
		if (signatureList.getLength() > 0) {
			Set<Node> nodeSet = new HashSet<Node>();
			for (int i = 0; i < signatureList.getLength(); i++) {
				/*
				 * É verificado se a assinatura corrente já foi adicionada ao
				 * conjunto. Caso já, simplesmente é passado para o próximo item
				 * da lista.
				 */
				if (nodeSet.add(signatureList.item(i))) {
					sum++;
					/*
					 * Quando é possível inferir que as assinaturas são
					 * contra-assinaturas então elas são adicionadas ao conjunto
					 * sem serem contabilizadas.
					 */
					Element signature = (Element) signatureList.item(i);
					NodeList counterSignatureList = signature
							.getElementsByTagName("ds:Signature");
					if (counterSignatureList.getLength() == 0) {
						counterSignatureList = signature.getElementsByTagName("Signature");
					}

					for (int j = 0; j < counterSignatureList.getLength(); j++)
						nodeSet.add(counterSignatureList.item(j));
				}
			}
		}
		return sum;
	}

	/**
	 * Retorna o documento contido dentro desse SignatureContainer em forma de
	 * <code>byte[]</code>. Esse método é útil quando se quer gravar as
	 * assinaturas em disco.
	 */
	public byte[] getBytes() throws EncodingException {
		ByteArrayOutputStream output = null;
		try {
			Transformer transformer = TransformerFactory.newInstance()
					.newTransformer();
			output = new ByteArrayOutputStream();
			transformer.transform(new DOMSource(this.xml), new StreamResult(
					output));
		} catch (Exception e) {
			throw new EncodingException(e);
		}
		return output.toByteArray();
	}

	/**
	 * Retorna o arquivo em formato OutputStream
	 * @param outputStream O stream que conterá a assinatura
	 * @throws EncodingException Exceção caso haja algum problema na conversão dos dados
	 *         do arquivo para o stream
	 */
	public void encode(OutputStream outputStream) throws EncodingException {
		try {
			Transformer transformer = TransformerFactory.newInstance()
					.newTransformer();
			transformer.transform(new DOMSource(this.xml), new StreamResult(
					outputStream));
		} catch (Exception e) {
			throw new EncodingException(e);
		}
	}

	/**
	 * Verifica se o arquivo possui alguma assinatura com conteúdo destacado sem considerar contra-assinaturas
	 * @return Indica se o arquivo possui conteúdo destacado
	 */
	public boolean hasDetachedContent() {
		int count = this.getSignatureCount();
		int i = 0;
		boolean hasDetachedContent = false;
		while (i < count && !hasDetachedContent) {
			XadesSignature signature = this.getSignatureAt(i);
			hasDetachedContent = signature.isExternalSignedData();
			i++;
		}
		return hasDetachedContent;
	}

	/**
	 * Retorna o formato da assinatura (XAdES)
	 * @return Retorna o formato da assinatura
	 */
	public SignatureFormat getFormat() {
		return SignatureFormat.XAdES;
	}

	/**
	 * Retorna o modo da assinatura
	 * @param index O índice da assinatura dentro do contêiner
	 * @return O modo da assinatura
	 * @throws SignatureModeException Exceção caso seja um modo inválido
	 */
	public ContainedSignatureMode getMode(Integer index)
			throws SignatureModeException {
		return this.getSignatureAt(index).getMode();
	}

	/**
	 * Retorna as assinaturas no arquivo sem considerar contra-assinaturas
	 * @return As assinaturas no arquivo
	 */
	public List<XadesSignature> getSignatures() throws EncodingException {
		ArrayList<XadesSignature> listOfSignatures = new ArrayList<XadesSignature>();
		for (int i = 0; i < this.getSignatureCount(); i++) {
			listOfSignatures.add(getSignatureAt(i));
		}
		return listOfSignatures;
	}

	/**
	 * Atribue o valor do conteúdo assinado
	 * @param content Os bytes do conteúdo assinado
	 */
	public void setContent(byte[] content) {
		this.content = content;
	}

	/**
	 * Retorna o conteúdo assinado
	 * @return Os bytes do conteúdo assinado
	 */
	byte[] getContent() {
		return this.content;
	}

}
