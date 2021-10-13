/*

ODesenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.TimeStampException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo IndividualDataObjectsTimeStamp qualifica os atributos de dados
 * assinados.
 * Este atributo contém um carimbo do tempo que é computado antes da produção da
 * assinatura sobre uma sequência formada por ALGUNS elementos ds:Reference
 * dentro do elemento ds:SignedInfo.
 * 
 * Esquema do atributo IndividualDataObjectsTimeStamp retirado do ETSI TS 101
 * 903:
 *
 * {@code
 * <xsd:element name="IndividualDataObjectsTimeStamp" type="XAdESTimeStampType"/>
 * }
 */
public class IndividualDataObjectsTimeStamp extends SignatureTimeStamp implements SignatureAttribute {

    public static final String IDENTIFIER = "IndividualDataObjectsTimeStamp";
    /**
     * Lista de nodos de referência
     */
    private List<Element> referenceElements;

    // private List<IncludeType> includeList;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usaddo no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * 
     * @param signatureVerifier Usado para criar e verificar o atributo.
     * @param index Índice usado para selecionar o atributo.
     * 
     * @throws SignatureAttributeException
     */
    public IndividualDataObjectsTimeStamp(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        super(signatureVerifier, index);
    }

    public IndividualDataObjectsTimeStamp(ContentInfo contentInfo, List<Element> referenceElements) {
        super(contentInfo);
        this.referenceElements = referenceElements;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IndividualDataObjectsTimeStamp.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        // TODO - verificar esse método.

        TimeStampToken timeStampToken = this.buildTimeStampToken();
        CertStore certStore = this.signatureVerifier.getCertStore();
        ArrayList<X509Certificate> certificateOfTimeStampTokenSidList;
        try {
        	
        	X509CertSelector selector = new X509CertSelector();
			try {
				selector.setIssuer(new X500Principal(timeStampToken.getSID()
						.getIssuer().getEncoded()));
			} catch (IOException e) {
				throw new SignatureAttributeException(e);
			}
			selector.setSerialNumber(timeStampToken.getSID().getSerialNumber());
        	
            certificateOfTimeStampTokenSidList = new ArrayList(certStore.getCertificates(selector));
        } catch (CertStoreException certStoreException) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Certificados no repositório não encontrados", certStoreException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        if (certificateOfTimeStampTokenSidList.size() == 0) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Os certificados do caminho de certificação do carimbo do tempo não foram encontrados");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        X509Certificate timeStampAutorityCert = certificateOfTimeStampTokenSidList.get(0);
        try {
            if (!timeStampToken.isSignatureValid(this.createSignerInformationVerifier(timeStampAutorityCert))) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "Carimbo de tempo inválido. Carimbadora: " + timeStampAutorityCert.getSubjectX500Principal());
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        } catch (TSPException tspException) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException("Carimbo de tempo inválido",
                    tspException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        } catch (OperatorCreationException operatorCreationException) {
            TimeStampException timeStampException = new TimeStampException("Falha ao validar o atributo carimbo de tempo. Carimbadora: "
                    + timeStampAutorityCert.getSubjectX500Principal(), operatorCreationException);
            timeStampException.setCritical(this.isSigned());
            throw timeStampException;
        } catch (CMSException cmsException) {
            TimeStampException timeStampException = new TimeStampException("Falha ao validar o atributo carimbo de tempo. Carimbadora: "
                    + timeStampAutorityCert.getSubjectX500Principal(), cmsException);
            timeStampException.setCritical(this.isSigned());
            throw timeStampException;
        }

        List<String> uris = new ArrayList<String>();
        // A regra para o INCLUDE é descrita no documento do ETSI TS 101 903 -
        // item 7.1.4.3.1
        throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_IS_NOT_IMPLEMENTED_YET);
        // FIXME - JAXB dependencies
        // for(IncludeType include : this.includeList) {
        // boolean referencedData = include.isReferencedData();
        // if(!referencedData)
        // throw new
        // TimeStampException("Falha ao validar o carimbo de tempo IndividualDataObjectsTimeStamp. Os campos referencedData devem estar \"true\"");
        // uris.add(include.getURI());
        // }
        // byte[] messageImprintBytes =
        // timeStampToken.getTimeStampInfo().getMessageImprintDigest();
        //
        // System.out.println("======= INICIO ========");
        // System.out.println("bytes do messageimprint: \n" + new
        // String(messageImprintBytes));
        // System.out.println("bytes do messageimprint: \n" + new
        // String(Base64.encode(messageImprintBytes)));
        //
        //
        // XadesSignature xadesSignature = (XadesSignature)
        // this.signatureVerifier.getSignature();
        // String hashAlgorithmId =
        // timeStampToken.getTimeStampInfo().getMessageImprintAlgOID();
        //
        // byte[] referencesHash =
        // xadesSignature.getReferencesHashValue(hashAlgorithmId, uris);
        // System.out.println("- - - - - - -");
        //
        // System.out.println("bytes das referencias: \n" + new
        // String(referencesHash));
        // System.out.println("bytes das referencias: \n" + new
        // String(Base64.encode(referencesHash)));
        // System.out.println("======= FIM ========");
        //
        // int comparationResult = compareBytes(messageImprintBytes,
        // referencesHash);
        // if (comparationResult != 0) {
        // TimeStampException timeStampException = new
        // TimeStampException("O valor do resumo criptográfico do carimbo do tempo é diferente do resumo das referências relacionadas com este carimbo.");
        // timeStampException.setCritical(this.isSigned());
        // throw timeStampException;
        // }
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {
        // FIXME - JAXB dependencies
        throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_IS_NOT_IMPLEMENTED_YET);
        // XAdESTimeStampType timeStamp = new XAdESTimeStampType();
        // EncapsulatedPKIDataType timeStampEncapsulated = new
        // EncapsulatedPKIDataType();
        // timeStampEncapsulated.setEncoding("der");
        // try{
        // timeStampEncapsulated.setValue(this.contentInfo.getEncoded());
        // }catch(IOException ioException){
        // throw new SignatureAttributeException(ioException.getMessage(),
        // ioException.getStackTrace());
        // }
        // timeStamp.getEncapsulatedTimeStampOrXMLTimeStamp().add(timeStampEncapsulated);
        //
        // for(Element referenceElement : this.referenceElements) {
        // String uri = referenceElement.getAttribute("Id");
        // boolean referencedData = true;
        // IncludeType include = new IncludeType();
        // include.setReferencedData(referencedData);
        // include.setURI(uri);
        // timeStamp.getInclude().add(include);
        // }
        // Element signatureTimeStampElement;
        // try{
        // signatureTimeStampElement =
        // Marshaller.marshallAttribute(this.getIdentifier(),
        // XAdESTimeStampType.class, timeStamp,
        // NamespacePrefixMapperImp.XADES_NS);
        // }catch(XmlProcessingException xmlProcessingException){
        // throw new
        // SignatureAttributeException(xmlProcessingException.getMessage(),
        // xmlProcessingException.getStackTrace());
        // }
        // return signatureTimeStampElement;
    }

    /**
     * Constrói um objeto {@link IndividualDataObjectsTimeStamp}
     * @param timestampNode O atributo codificado
     * @throws SignatureAttributeException
     */
    @Override
    public void decode(Element timestampNode) throws SignatureAttributeException {
        throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_IS_NOT_IMPLEMENTED_YET);
        // FIXME - JAXB Dependencies
        // NodeList encapsulatedTimeStampList;
        // encapsulatedTimeStampList =
        // timestampNode.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
        // "EncapsulatedTimeStamp");
        // try {
        // this.contentInfo = new ContentInfo((ASN1Sequence)
        // DERSequence.fromByteArray(Base64.decode(encapsulatedTimeStampList.item(0).getTextContent())));
        // } catch (DOMException domException) {
        // throw new SignatureAttributeException(domException.getMessage(),
        // domException.getStackTrace());
        // } catch (IOException ioException) {
        // throw new SignatureAttributeException(ioException.getMessage(),
        // ioException.getStackTrace());
        // }
        //
        // NodeList includeNodeList =
        // timestampNode.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
        // "Include");
        //
        // this.includeList = new ArrayList<IncludeType>();
        // for(int i = 0; i < includeNodeList.getLength(); i++) {
        // IncludeType include = new IncludeType();
        // Element includeElement = (Element) includeNodeList.item(i);
        // boolean referencedData =
        // "true".equals(includeElement.getAttribute("referencedData"));
        // include.setReferencedData(referencedData);
        // include.setURI(includeElement.getAttribute("URI"));
        // this.includeList.add(include);
        // }

    }

    /**
     * Informa se o atributo é assinado.
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return true;
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return false;
    }
}
