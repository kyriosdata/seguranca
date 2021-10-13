package br.ufsc.labsec.signature.signer.signatureSwitch;

import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.signer.SignerType;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.io.InputStream;

public abstract class SignatureDataWrapperGenerator {

    public SignatureDataWrapperGenerator() { }

    /**
     * @return the signed document bytes.
     */
    public abstract SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policyOid);
}
