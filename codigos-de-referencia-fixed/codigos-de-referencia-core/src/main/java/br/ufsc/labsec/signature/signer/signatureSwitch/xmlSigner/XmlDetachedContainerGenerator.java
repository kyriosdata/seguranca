package br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureComponent;

import org.apache.commons.io.IOUtils;
import org.w3c.dom.Document;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.util.logging.Level;

/**
 * Esta classe gera assinaturas XML destacadas
 */
public class XmlDetachedContainerGenerator extends XmlContainerGenerator {

    /**
     * Construtor
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    public XmlDetachedContainerGenerator(XmlSignatureComponent xmlSignatureComponent) {
        super(xmlSignatureComponent);
    }

    /**
     * Gera a assinatura
     * @param url A URL do arquivo a ser assinado
     * @return O arquivo de assinatura
     * @throws MarshalException Exceção quando há erro na manipulação da estrututra XML
     * @throws XMLSignatureException Exceção quando há erro durante o processo de assinatura
     */
    @Override
    public InputStream sign(String url) throws MarshalException, XMLSignatureException {

        if(url.startsWith("https")) {
            url = url.replaceFirst("^https", "http");
        }

        Document document = buildEmptyDocument();
        SignedInfo signedInfo = buildSignedInfo(buildReference(url));
        KeyInfo keyInfo = buildKeyInfo();
        XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
        DOMSignContext domSignContext = new DOMSignContext(privateKey, document);

        signature.sign(domSignContext);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        transform(document, outputStream);

        return new ByteArrayInputStream(outputStream.toByteArray());
    }

    /**
     * Gera a assinatura
     * @param inputStream O arquivo a ser assinado
     * @return O arquivo de assinatura
     * @throws MarshalException Exceção quando há erro na manipulação da estrututra XML
     * @throws XMLSignatureException Exceção quando há erro durante o processo de assinatura
     */
    public InputStream sign(InputStream inputStream) throws MarshalException, XMLSignatureException {
        Document document = buildEmptyDocument();
        SignedInfo signedInfo = buildSignedInfo(buildReference(inputStream));
        KeyInfo keyInfo = buildKeyInfo();
        XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
        DOMSignContext domSignContext = new DOMSignContext(privateKey, document);

        signature.sign(domSignContext);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        transform(document, outputStream);

        return new ByteArrayInputStream(outputStream.toByteArray());
    }

    /**
     * Gera a referência do arquivo a ser assinado
     * @param url A URL do arquivo a ser assinado
     * @return A referência gerada
     */
    public Reference buildReference(String url) {
        try {
            return signatureFactory.newReference
                    (url,
                            signatureFactory.newDigestMethod(DigestMethod.SHA256,
                                    null));
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        return null;
    }

    /**
     * Gera a referência da assinatura
     * @return A referência gerada
     */
    public Reference buildReference(InputStream inputStream) {
        Reference reference = null;
        try {
            DigestMethod digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA256, null);
            reference = signatureFactory.newReference
                    (this.getFilename(), digestMethod,
                            null,null, null,
                            this.getFileDigest(inputStream, digestMethod));
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | ToBeSignedException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }

        return reference;
    }

    /**
     * Retorna o nome do arquivo a ser assinado
     * @return O nome do arquivo a ser assinado
     */
    private String getFilename() {
        String filename = this.xmlSignatureComponent.getSigner().getFilename();
        int index = filename.lastIndexOf("/");
        return filename.substring(index+1);
    }

    /**
     * Retorna o resumo criptográfico do arquivo a ser assinado
     * @param inputStream O arquivo a ser assinado
     * @param digestMethod o algoritmo de resumo
     * @return O resumo criptográfico do arquivo
     * @throws ToBeSignedException exceção em caso de parâmetros inválidos ou erro durante
     * a realização do resumo
     */
    private byte[] getFileDigest(InputStream inputStream, DigestMethod digestMethod) throws ToBeSignedException {
        MessageDigest digester;
        byte[] fileBytes;
        try {
            digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(digestMethod
                    .getAlgorithm()));
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new ToBeSignedException("Algoritmo desconhecido", noSuchAlgorithmException);
        }
        try {
            fileBytes = IOUtils.toByteArray(inputStream);
        } catch (IOException e) {
            throw new ToBeSignedException("Erro ao ler o arquivo", e);
        }
        return digester.digest(fileBytes);
    }
}
