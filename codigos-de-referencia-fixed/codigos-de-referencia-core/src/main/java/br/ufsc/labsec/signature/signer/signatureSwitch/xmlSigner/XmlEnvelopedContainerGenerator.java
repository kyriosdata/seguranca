package br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureComponent;
import org.w3c.dom.Document;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.*;
import java.util.Collections;
import java.util.logging.Level;

/**
 * Esta classe gera assinaturas XML embarcadas
 */
public class XmlEnvelopedContainerGenerator extends XmlContainerGenerator {

    /**
     * Construtor
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    public XmlEnvelopedContainerGenerator(XmlSignatureComponent xmlSignatureComponent) {
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

        SignedInfo signedInfo = buildSignedInfo(buildReference());
        KeyInfo keyInfo = buildKeyInfo();
        XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
        DOMSignContext domSignContext = new DOMSignContext(privateKey, document.getDocumentElement());

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
                    ("", signatureFactory.newDigestMethod(DigestMethod.SHA256, null),
                            Collections.singletonList
                                    (signatureFactory.newTransform
                                            (Transform.ENVELOPED, (TransformParameterSpec) null)),
                            null, null);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }

        return reference;
    }
}
