package br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureComponent;
import org.w3c.dom.Document;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.*;
import java.util.Collections;
import java.util.logging.Level;


/**
 * Esta classe gera assinaturas XML anexadas
 */
public class XmlEnvelopingContainerGenerator extends XmlContainerGenerator {

    /**
     * Construtor
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    public XmlEnvelopingContainerGenerator(XmlSignatureComponent xmlSignatureComponent) {
        super(xmlSignatureComponent);
    }

    /**
     * Gera a assinatura
     * @param inputStream O arquivo a ser assinado
     * @return O arquivo de assinatura
     * @throws MarshalException Exceção quando há erro na manipulação da estrututra XML
     * @throws XMLSignatureException Exceção quando há erro durante o processo de assinatura
     */
    public InputStream sign(InputStream inputStream) throws MarshalException, XMLSignatureException {

        Document document = buildDocument(inputStream);

        XMLStructure content = new DOMStructure(document.getDocumentElement());
        XMLObject object = signatureFactory.newXMLObject
                (Collections.singletonList(content),
                        "object",
                        null,
                        null);

        SignedInfo signedInfo = buildSignedInfo(buildReference());
        KeyInfo keyInfo = buildKeyInfo();
        DOMSignContext domSignContext = new DOMSignContext(privateKey, document);
        XMLSignature signature = signatureFactory.newXMLSignature
                (signedInfo,
                        keyInfo,
                        Collections.singletonList(object),
                        null,
                        null);

        signature.sign(domSignContext);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        transform(document, outputStream);

        return new ByteArrayInputStream(outputStream.toByteArray());
    }

    /**
     * Gera a referência da assinatura
     * @return A referência gerada
     */
    @Override
    public Reference buildReference() {
        Reference reference = null;

        try {
            reference = signatureFactory.newReference
                    ("#object", signatureFactory.newDigestMethod
                            (DigestMethod.SHA256,
                                    null));
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }

        return reference;
    }
}
