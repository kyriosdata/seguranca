package br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureComponent;
import br.ufsc.labsec.signature.signer.suite.SingletonSuiteMapper;
import org.w3c.dom.*;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.*;
import java.util.Collections;
import java.util.logging.Level;

/**
 * Esta classe gera assinaturas XML internamente destacadas
 */
public class XmlInternallyDetachedContainerGenerator extends XmlContainerGenerator {

    /**
     * Construtor
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    public XmlInternallyDetachedContainerGenerator(XmlSignatureComponent xmlSignatureComponent) {
        super(xmlSignatureComponent);
    }

    /**
     * Gera a assinatura
     * @param inputStream O arquivo a ser assinado
     * @return O arquivo de assinatura
     * @throws MarshalException Exceção quando há erro na manipulação da estrututra XML
     * @throws XMLSignatureException Exceção quando há erro durante o processo de assinatura
     */
    public InputStream sign(InputStream inputStream) throws XPathExpressionException, ParserConfigurationException, MarshalException, XMLSignatureException {
        Document toBeSigned = buildDocument(inputStream);

        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xpath = xPathFactory.newXPath();

        XPathExpression exprAssertion = xpath.compile("/*");
        Element assertionNode = (Element) exprAssertion.evaluate(toBeSigned, XPathConstants.NODE);

        String correctID = "id";
        NodeList nodeList = (NodeList) xpath.evaluate("/*/@*", toBeSigned, XPathConstants.NODESET);
        int length = nodeList.getLength();
        for( int i = 0; i < length; i++) {
            Attr attr = (Attr) nodeList.item(i);
            String name = attr.getName();
            if(name.toLowerCase().equals(correctID)) {
                correctID = name;
            }
        }

        XPathExpression exprAssertionID = xpath.compile("/*/@"+correctID+"");
        String assertionID = (String) exprAssertionID.evaluate(toBeSigned, XPathConstants.STRING);

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

        Document rootDocument = documentBuilder.newDocument();
        Element rootElement = rootDocument.createElement("internally-detached");
        Node importedNode = rootDocument.importNode(assertionNode, true);
        rootElement.appendChild(importedNode);
        rootDocument.appendChild(rootElement);

        exprAssertion = xpath.compile("/*/*");
        assertionNode = (Element) exprAssertion.evaluate(rootDocument, XPathConstants.NODE);
        assertionNode.setIdAttribute(correctID, true);

        DOMSignContext domSignContext = new DOMSignContext(privateKey, rootElement);

        Reference reference = buildReference(assertionID);
        SignedInfo signedInfo = buildSignedInfo(reference);
        KeyInfo keyInfo = buildKeyInfo();

        XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(domSignContext);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        transform(rootDocument, outputStream);

        return new ByteArrayInputStream(outputStream.toByteArray());
    }

    /**
     * Constrói as informações do assinante a partir da referência dada
     * @param reference A referência
     * @return As informações do assinante
     */
    @Override
    public SignedInfo buildSignedInfo(Reference reference) {
        String algorithm = SUITE_MAPPER.signatureAlgorithms.get(signatureSuite);
        SignedInfo signedInfo = null;

        try {
            CanonicalizationMethod canonicalizationMethod =
                    signatureFactory.newCanonicalizationMethod
                            (CanonicalizationMethod.EXCLUSIVE,
                                    (C14NMethodParameterSpec) null);
            signedInfo = signatureFactory.newSignedInfo
                    (canonicalizationMethod,
                            signatureFactory.newSignatureMethod(algorithm, null),
                            Collections.singletonList(reference));
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }

        return signedInfo;
    }

    /**
     * Gera a referência do nodo a ser assinado
     * @param assertionID O identificador do nodo assinado
     * @return A referência gerada
     */
    public Reference buildReference(String assertionID) {
        Reference reference = null;

        try {
            reference = signatureFactory.newReference("#" + assertionID,
                    signatureFactory.newDigestMethod(DigestMethod.SHA1,
                            null),
                    Collections.singletonList(
                            signatureFactory.newTransform(
                                    Transform.ENVELOPED, (TransformParameterSpec) null)),
                    null,
                    null);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }

        return reference;
    }
}