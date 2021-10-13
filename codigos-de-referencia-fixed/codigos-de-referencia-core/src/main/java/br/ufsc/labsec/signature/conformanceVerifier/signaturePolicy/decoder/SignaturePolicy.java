/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;


///**
// * SignaturePolicy ::= SEQUENCE {
// * signPolicyHashAlg AlgorithmIdentifier,
// * signPolicyInfo SignPolicyInfo,
// * signPolicyHash SignPolicyHash OPTIONAL }
// */
///**
// * <xsd:element name="SignaturePolicy" type="SignaturePolicyType"/>
// * <xsd:complexType name="SignaturePolicyType">
// * <xsd:sequence>
// * <xsd:element name="SignPolicyDigestAlg" type="ds:DigestMethodType"/>
// * <xsd:element ref="ds:Transforms" minOccurs="0"/>
// * <xsd:element name="SignPolicyInfo" type="SignaturePolicyInfoType"/>
// * <xsd:element name="SignPolicyDigest" type="ds:DigestValueType" minOccurs="0"/>
// * </xsd:sequence>
// * </xsd:complexType>
// */
/**
 * Este atributo é o atributo raiz da Política de Assinatura.
 */
public class SignaturePolicy {

    /**
     * O identificador do algoritmo usado no cálculo de hash da política
     */
    private AlgorithmIdentifier signPolicyHashAlg;
    /**
     * Informações da política
     */
    private SignaturePolicyInfo signPolicyInfo;
    /**
     * Valor do hash da política
     */
    private byte[] signPolicyHash;
    /**
     * Valor dos bytes da política
     */
    private byte[] encoded;
    /**
     * As transformações feitas
     */
    private Transforms transforms;
    /**
     * Indica se a política é XML
     */
    private boolean isXML;
    /**
     * Arquivo XML da política, se a mesma for XML
     */
    private Document signPolicyDocument;
    /**
     * Nodo XML que contém as informações da política
     */
    private Node signPolicyInfoNode;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param derEncoded codificação ASN1 do atributo {@link SignaturePolicy}.
     * @throws ParseException Exceção em caso de erro no parsing da data no atributo
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public SignaturePolicy(byte[] derEncoded) throws IOException, ParseException, CertificateException, NoSuchAlgorithmException {
        this.isXML = false;
        this.encoded = derEncoded;
        ASN1Sequence signaturePolicy = (ASN1Sequence) ASN1Sequence.fromByteArray(derEncoded);
        this.signPolicyHashAlg = new AlgorithmIdentifier((ASN1Sequence) signaturePolicy.getObjectAt(0));
        this.signPolicyInfo = new SignaturePolicyInfo((ASN1Sequence) signaturePolicy.getObjectAt(1));
        this.signPolicyHash = null;
        if (signaturePolicy.size() == 3) {
            DEROctetString octetString = (DEROctetString) signaturePolicy.getObjectAt(2);
            this.signPolicyHash = octetString.getOctets();
        }
    }

    /**
     * Retorna os bytes da política
     * @return array de bytes da política
     */
    public byte[] getEncoded() {
       return encoded;
    }

    /**
     * Atribui os bytes da política
     * @param encoded Bytes da política
     */
    public void setEncoded(byte[] encoded) {
        this.encoded = encoded;
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param xmlEncoded elemento XML que representa o atributo
     *            {@link SignaturePolicy} .
     * @throws DOMException Exceção em caso de erro no elemento XML
     * @throws ParseException Exceção em caso de erro no parsing da data no atributo
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public SignaturePolicy(Document xmlEncoded) throws DOMException, ParseException, CertificateException, IOException,
            NoSuchAlgorithmException{

        this.signPolicyDocument = xmlEncoded;
        this.isXML = true;
        Node node = xmlEncoded.getChildNodes().item(0);
        this.signPolicyHashAlg = null;
        this.transforms = null;
        this.signPolicyHashAlg = new AlgorithmIdentifier(node.getChildNodes().item(0));
        Element element = (Element) node.getChildNodes().item(1);
        if (element.getTagName().equals("ds:Transforms")) {
            this.transforms = new Transforms(element);
            this.signPolicyInfoNode = node.getChildNodes().item(2);
            this.signPolicyInfo = new SignaturePolicyInfo(this.signPolicyInfoNode);
            if (node.getChildNodes().getLength() == 4) {
                this.signPolicyHash = Base64.decode(node.getChildNodes().item(3).getTextContent().getBytes());
            }
        } else {
            this.signPolicyInfo = new SignaturePolicyInfo(node.getChildNodes().item(1));
            if (node.getChildNodes().getLength() == 3) {
                this.signPolicyHash = Base64.decode(node.getChildNodes().item(2).getTextContent().getBytes());
            }
        }
    }

    /**
     * Verifica se existe o atributo <code>Transforms</code>.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasTransforms() {
        return this.transforms != null;
    }

    /**
     * Retorna o atributo <code>SignPolicyHashAlg</code>.
     * @return O valor do atributo
     */
    public AlgorithmIdentifier getSignPolicyHashAlg() {
        return this.signPolicyHashAlg;
    }

    /**
     * Retorna o atributo <code>SignPolicyInfo</code>.
     * @return O valor do atributo
     */
    public SignaturePolicyInfo getSignPolicyInfo() {
        return this.signPolicyInfo;
    }

    /**
     * Retorna o atributo <code>SignPolicyHash</code>.
     * @return O valor do atributo
     */
    public byte[] getSignPolicyHash() {
        return this.signPolicyHash;
    }

    /**
     * Verifica se existe o atributo <code>SignPolicyHash</code>.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasSignPolicyHash() {
        return this.signPolicyHash != null;
    }

    /**
     * Retorna o atributo <code>Transforms</code>.
     * @return O valor do atributo
     */
    public Transforms getTransforms() {
        return this.transforms;
    }

    /**
     * Verifica se a Política de Assinatura é XML
     * @return Indica se a Política de Assinatura é XML
     */
    public boolean isXML() {
        return this.isXML;
    }

    public boolean validateHash() throws NoSuchAlgorithmException, IOException, TransformerFactoryConfigurationError {
        if (isXML()) {
            // FIXME a validação de PAs XMLs está incorreta, é necessário corrigir a implementação do extractXMLHash.
            return true;
        } else {
            byte[] signPolicyHashBytes = extractASN1Hash(this.signPolicyInfo, this.signPolicyHashAlg);
            boolean isValid = compareBytes(signPolicyHashBytes, this.signPolicyHash);
            return isValid;
        }
    }

    /**
     * Calcula o resumo criptográfico das informações da política a partir do arquivo XML
     * @param algorithmIdentifier O algoritmo a ser utilizado no cálculo
     * @return Os bytes de hash
     * @throws TransformerFactoryConfigurationError Exceção em caso de erro no documento XML
     * @throws TransformerException Exceção em caso de erro no documento XML
     * @throws NoSuchAlgorithmException Exceção em cado de algoritmo inválido
     */
    private byte[] extractXmlHash(AlgorithmIdentifier algorithmIdentifier) throws TransformerFactoryConfigurationError,
        TransformerException, NoSuchAlgorithmException {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(this.signPolicyDocument), new StreamResult(output));
        String outputString = output.toString();

        int beginOfSignPolicyInfoIndex = outputString.indexOf("<pa:SignPolicyInfo");
        int endOfSignPolicyInfoIndex = outputString.indexOf("</pa:SignPolicyInfo>") + "</pa:SignPolicyInfo>".length();
        byte[] signPolicyHashBytes = null;

        if (beginOfSignPolicyInfoIndex != -1 && endOfSignPolicyInfoIndex != -1) {
            String policyInfoString = outputString.substring(beginOfSignPolicyInfoIndex, endOfSignPolicyInfoIndex);
            byte[] policyInfoBytes = policyInfoString.getBytes();

            String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmIdentifier.getAlgorithm());
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(policyInfoBytes);
            signPolicyHashBytes = messageDigest.digest();

        }
        return signPolicyHashBytes;
    }

    /**
     * Verifica se os bytes são iguais
     * @param expected O byte experado
     * @param actual O byte atual
     * @return Indica se são iguais
     */
    public static boolean compareBytes(byte[] expected, byte[] actual) {
        boolean result = expected.length == actual.length;
        int i = 0;
        while (result && i < expected.length) {
            result &= expected[i] == actual[i];
            i++;
        }
        return result;
    }

    /**
     * Calcula o resumo criptográfico das informações da política
     * @param signPolicyInfo As informações da política
     * @param algorithm O algoritmo a ser utilizado no cálculo
     * @return Os bytes de hash
     * @throws IOException Exceção em caso de erro no cálculo
     * @throws NoSuchAlgorithmException Exceção em cado de algoritmo inválido
     */
    protected byte[] extractASN1Hash(SignaturePolicyInfo signPolicyInfo, AlgorithmIdentifier algorithm) throws IOException,
        NoSuchAlgorithmException {
        byte[] algHash = algorithm.getAlgorithmSequence().getEncoded();

        ASN1Sequence signPolicyInfoAsn1Object = signPolicyInfo.getSignPolicyInfoAsn1Object();
        byte[] infoHash = signPolicyInfoAsn1Object.getEncoded();
        int size = algHash.length + infoHash.length;
        byte[] signPolicyBytes = new byte[size];
        for (int index = 0; index < size; index++) {
            if (index < algHash.length) {
                signPolicyBytes[index] = algHash[index];
            } else {
                signPolicyBytes[index] = infoHash[index - algHash.length];
            }
        }
        String algorithmName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm.getAlgorithm());
        MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
        messageDigest.update(signPolicyBytes);
        byte[] signPolicyHashBytes = messageDigest.digest();
        return signPolicyHashBytes;
    }

    final protected static char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * Transforma o valor dos bytes dados em hexadecimal
     * @param bytes O array de bytes
     * @return O valor em hexadecimal
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
