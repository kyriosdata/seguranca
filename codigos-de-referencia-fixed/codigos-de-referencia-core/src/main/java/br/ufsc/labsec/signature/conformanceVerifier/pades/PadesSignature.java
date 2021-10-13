package br.ufsc.labsec.signature.conformanceVerifier.pades;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.DocTimeStampAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.DssAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.PadesAttribute;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.util.encoders.Hex;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

/**
 * Esta classe representa uma assinatura PAdES.
 */
public class PadesSignature {

    /**
     * O documento assinado
     */
    private PDDocument document;
    /**
     * A assinatura PAdES
     */
    private PDSignature signature;
    /**
     * Bytes do documento
     */
    private byte[] pdfBytes;
    /**
     * Lista de carimbo de tempo
     */
    private List<PDSignature> docTimeStampList;
    /**
     * Dicionário DSS
     */
    private COSDictionary dssDictionary;
    /**
     * Resumo criptográfico da assinatura
     */
    private String vriHash;
    /**
     * Tipo da assinatura
     */
    private String signatureType;
    /**
     * Último byte do carimbo de tempo
     */
    private int lastByteRangeDocTS;

    /**
     * Construtor
     * @param document O documento assinado
     * @param signature A assinatura PAdES
     * @param pdfBytes Bytes do documento
     */
    public PadesSignature(PDDocument document, PDSignature signature, byte[] pdfBytes) {
        this.document = document;
        this.signature = signature;
        this.pdfBytes = pdfBytes;
        this.docTimeStampList = new ArrayList<PDSignature>();

        COSName cosname = (COSName) this.signature.getCOSObject().getDictionaryObject("Type");
        this.signatureType = cosname.getName();
        calculeHashSig();
    }

    /**
     * Retorna Encontra na estrutura do pdf o dicionário de DSS da assinatura
     * @param pdDocument Indica o documento onde deve ser retirado o dicionário
     * @return {@link COSDictionary} de DSS da assinatura
     */
    public COSDictionary getDssDictionary(PDDocument pdDocument) {
        PDDocumentCatalog catalog = pdDocument.getDocumentCatalog();
        COSDictionary baseObject = catalog.getCOSObject();
        return (COSDictionary) baseObject.getDictionaryObject("DSS");
    }

    /**
     * Retorna a lista de atributos da assinatura
     * @param last Indica se a assinatura é a última do documento
     * @return A lista de atributos da assinatura
     */
    public List<String> getAttributeList(boolean last) {
        List<String> attributes = new ArrayList<String>();
        List<PDSignature> signatures = null;
        int[] signatureByteRange = this.signature.getByteRange();

        int prevSigByteRange = -1;
        try {
            //Procura por DocTimeStamp
            signatures = this.document.getSignatureDictionaries();

            for (PDSignature sigDic : signatures) {
                COSName attType = (COSName) sigDic.getCOSObject().getDictionaryObject("Type");
                if (attType.getName().equals("Sig")) {
                    int[] attByteRange = sigDic.getByteRange();
                    if (attByteRange[1] >= signatureByteRange[1]) {
                        if (attByteRange[1] > prevSigByteRange) {
                            prevSigByteRange = attByteRange[1];
                        }
                    }
                }
            }

            for (PDSignature sigDic : signatures) {
                int[] attByteRange = sigDic.getByteRange();
                //Se é um docTimeStamp
                COSName attType = (COSName) sigDic.getCOSObject().getDictionaryObject("Type");
                if (attType.getName().equals("DocTimeStamp")) {
                    //Se o byteArray do docTimeStamp for maior que o da assinatura
                    //Ou seja, se o docTimeStamp protege a assinatura
                    if (attByteRange[1] >= signatureByteRange[1]) {
                        if (attByteRange[1] < prevSigByteRange || last) {
                            attributes.add("DocTimeStamp");
                            this.docTimeStampList.add(sigDic);
                        }
                    }
                }
            }

            COSDictionary dssDictionary = getDssDictionary(this.document);
            if (dssDictionary != null) {
                attributes.add("DSS");
                this.dssDictionary = dssDictionary;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return attributes;
    }

    /**
     * Retorna um objeto do atributo desejado
     * @param identifier O identificador do atributo
     * @param verifier O verificador de assinatura PAdES
     * @return Um objeto do atributo desejado
     */
    public PadesAttribute getEncodedAttribute(String identifier, PadesSignatureVerifier verifier) {
        PadesAttribute attribute = null;

        if (identifier.equals("DocTimeStamp")) {
            PDSignature dic = this.selectDocTimeStamp();
            String hash = calculeHashDocTS(dic);
            attribute = new DocTimeStampAttribute(verifier, dic, hash);
        } else if (identifier.equals("DSS")) {
            String signatureHash = this.vriHash;
            if (this.dssDictionary == null) {
                this.dssDictionary = getDssDictionary(this.document);
            }
            attribute = new DssAttribute(verifier, this.dssDictionary, signatureHash);
        }

        return attribute;
    }

    /**
     * Calcula o resumo criptográfico do carimbo de tempo
     * @param dic O carimbo de tempo
     * @return O resumo criptográfico do carimbo de tempo
     */
    private String calculeHashDocTS(PDSignature dic) {
        byte[] contents = null;
        byte[] bytes = null;
        String hash = null;
        try {
            contents = dic.getContents(this.pdfBytes);
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(contents);
            bytes = md.digest();
            hash = new String(Hex.encode(bytes));

        } catch (NoSuchAlgorithmException e) {
            Application.logger.log(Level.WARNING,
                    "Erro ao gerar o resumo para usar como chave do VRI.");
        } catch (IOException e) {
            Application.logger.log(Level.WARNING,
                    "Erro pegar os bytes da assinatura para usar como chave do VRI.");
        }

        return hash;

    }

    /**
     * Retorna os bytes da documento assinado
     * @return Os bytes do documento
     */
    public byte[] getPdfBytes() {
        return pdfBytes;
    }

    /**
     * Retorna o último carimbo de tempo da assinatura presente na lista de carimbos
     * @return O último carimbo de tempo da assinatura presente na lista de carimbos
     */
    private PDSignature selectDocTimeStamp() {
        PDSignature last = this.docTimeStampList.get(0);
        int lastIndex = 0;
        int[] lastByteRange = last.getByteRange();

        for (int i = 1; i < this.docTimeStampList.size(); i++) {
            PDSignature toCompare = this.docTimeStampList.get(i);
            int[] toCompareByteRange = toCompare.getByteRange();
            if (toCompareByteRange[1] > lastByteRange[1]) {
                last = toCompare;
                lastIndex = i;
                lastByteRange = toCompareByteRange;
            }
        }
        this.docTimeStampList.remove(lastIndex);
        return last;
    }

    /**
     * Retorna o tipo da assinatura
     * @return O tipo da assinatura
     */
    public String getSignatureType() {
        return signatureType;
    }

    /**
     * Identifica e atribue o último byte do carimbo de tempo
     */
    public void setLastByteRangeDocTS() {
        int last = 0;
        List<PDSignature> signatures = null;
        try {
            signatures = this.document.getSignatureDictionaries();
        } catch (IOException e) {
            e.printStackTrace();
        }
        for (PDSignature sigDic : signatures) {
            COSName attType = (COSName) sigDic.getCOSObject().getDictionaryObject("Type");
            if (attType.getName().equals("DocTimeStamp")) {
                int[] attByteRange = sigDic.getByteRange();
                if (attByteRange[1] > last) {
                    last = attByteRange[1];
                }
            }
        }
        this.lastByteRangeDocTS = last;
    }

    /**
     * Retorna o documento assinado
     * @return O documento assinado
     */
    public PDDocument getDocument() {
        return this.document;
    }

    /**
     * Calcula o resumo criptográfico da assinatura
     */
    private void calculeHashSig() {
        byte[] contents;
        byte[] bytes;
        try {
            if (this.signatureType.equals("Sig")) {
                contents = this.signature.getContents(this.pdfBytes);
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(contents);
                bytes = md.digest();
                this.vriHash = new String(Hex.encode(bytes));
            }
        } catch (NoSuchAlgorithmException e) {
            Application.logger.log(Level.WARNING,
                    "Erro ao gerar o resumo para usar como chave do VRI.");
        } catch (IOException e) {
            Application.logger.log(Level.WARNING,
                    "Erro uso dos bytes da assinatura para usar como chave do VRI.");
        }
    }

    /**
     * Retorna o último byte do carimbo de tempo
     * @return O último byte do carimbo de tempo
     */
    public int getLastByteRangeDocTS() {
        return lastByteRangeDocTS;
    }

}
