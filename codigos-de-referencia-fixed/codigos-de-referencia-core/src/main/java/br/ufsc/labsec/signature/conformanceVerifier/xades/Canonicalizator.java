package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.util.io.Streams;
import org.w3c.dom.DOMException;
import org.w3c.dom.Node;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 *  Esta classe aplica uma canonicalização aos nodos.
 */
public class Canonicalizator {

    /**
     * Canonicaliza o nodeValue e contatena os bytes no octetStream. Usado
     * quando já estiver uma assinatura, pois deve pegar o algoritmo de
     * canonização e passar como parâmetro.
     * 
     * @param nodeValue O nodo que será sofrerará a canonização
     * @param octetStream O octetstream em que o resultado da canonização e
     *            concatenação será colocado
     * @param canonicalizationMethodAlgorithm O algoritmo utilizado para
     *            canonizar
     * @throws SignatureAttributeException
     */
    public static void canonicalizationAndConcatenate(Node nodeValue, OutputStream octetStream, String canonicalizationMethodAlgorithm)
        throws SignatureAttributeException {
        OctetStreamData octetStreamData = getCanonicalization(nodeValue, canonicalizationMethodAlgorithm);
        try {
            concatenateOctetStream(octetStreamData.getOctetStream(), octetStream);
        } catch (IOException ioException) {
            throw new SignatureAttributeException(ioException);
        }
    }

    /**
     * Canonicaliza o nodeValue e contatena bytes no octetStream. Usado quando
     * ainda não se tem uma assinatura, assim é utilizado o método de
     * canonização padrão.
     * 
     * @param nodeValue o nodo que será sofrerará a canonização
     * @param octetStream o octetstream em que o resultado da canonização e
     *            concatenação será colocado
     * @throws SignatureAttributeException exceção em caso de algoritmo inválido ou erro na concatenação
     */
    public static void canonicalizationAndConcatenate(Node nodeValue, OutputStream octetStream) throws SignatureAttributeException {
        C14NMethodParameterSpec methodParameterSpec = null;
        CanonicalizationMethod canonicalizationMethod = null;
        try {
            canonicalizationMethod = XMLSignatureFactory.getInstance().newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                    methodParameterSpec);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(noSuchAlgorithmException);
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new SignatureAttributeException(invalidAlgorithmParameterException);
        }
        String canonicalizationMethodAlgorithm = canonicalizationMethod.getAlgorithm();
        OctetStreamData octetStreamData = getCanonicalization(nodeValue, canonicalizationMethodAlgorithm);
        try {
            concatenateOctetStream(octetStreamData.getOctetStream(), octetStream);
        } catch (IOException ioException) {
            throw new SignatureAttributeException(ioException);
        }
    }

    /**
     * Responsável por aplicar uma canonicalização a um determinado nodo
     * 
     * @param nodeValue o nodo que será canonalizado
     * @param canonicalizationMethodAlgorithm o algoritmo de canonização
     * @return um OctectStream com o resultado da canonização
     * @throws SignatureAttributeException exceção em caso de algoritmo inválido
     */
    public static OctetStreamData getCanonicalization(Node nodeValue, String canonicalizationMethodAlgorithm)
        throws SignatureAttributeException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Transformer transformer = null;
        try {
            transformer = TransformerFactory.newInstance().newTransformer();
        } catch (TransformerConfigurationException transformerConfigurationException) {
            throw new SignatureAttributeException(transformerConfigurationException.getMessage());
        } catch (TransformerFactoryConfigurationError transformerFactoryConfigurationError) {
            throw new SignatureAttributeException(transformerFactoryConfigurationError.getMessage());
        }
        try {
            transformer.transform(new DOMSource(nodeValue), new StreamResult(buffer));
        } catch (TransformerException transformerException) {
            throw new SignatureAttributeException(transformerException.getMessage(), transformerException.getStackTrace());
        }

        TransformService transformService = null;
        try {
            transformService = TransformService.getInstance(canonicalizationMethodAlgorithm, "DOM");
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(SignatureAttributeException.NO_SUCH_ALGORITHM);
        } catch (DOMException domException) {
            throw new SignatureAttributeException("Má formação do xml");
        }
        String cutBuffer = new String(buffer.toByteArray());
        cutBuffer = cutBuffer.substring(cutBuffer.indexOf("?>") + 2);
        Data data = new OctetStreamData(new ByteArrayInputStream(cutBuffer.getBytes()));
        OctetStreamData transformedXml = null;
        try {
            transformedXml = (OctetStreamData) transformService.transform(data, null);
        } catch (TransformException transformException) {
            throw new SignatureAttributeException(transformException.getMessage(), transformException.getStackTrace());
        }

        return transformedXml;
    }

    /**
     * Concatena os octet streams
     * 
     * @param inputStream o inputStream que será lido
     * @param octetStream o octetStream em que será concatenado
     * @throws IOException exceção em caso de erro na concatenação
     */
    private static void concatenateOctetStream(InputStream inputStream, OutputStream octetStream) throws IOException {
        byte[] bytes = Streams.readAll(inputStream);
        octetStream.write(bytes);
    }

    /**
     * Gera um resumo criptográfico (hash)
     * 
     * @param algorithm o algoritmo utilizado
     * @param bytesToDigest os bytes aos quais será aplicado o algoritmo de resumo
     * @return o hash dos bytes dados
     * 
     * @throws SignatureAttributeException exceção em caso de algoritmo inválido
     */
    public static byte[] getHash(String algorithm, byte[] bytesToDigest) throws SignatureAttributeException {
        byte[] result = null;
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(SignatureAttributeException.NO_SUCH_ALGORITHM);
        }
        result = digest.digest(bytesToDigest);
        return result;
    }
}
