package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IUException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.PossibleIncrementalUpdateException;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Esta classe representa uma transformação em um documento PDF.
 */
public abstract class Transformation extends PDDocumentUtils {

    private static String TRANSFORMATION_NOT_FOUND = "Transformação não encontrada";

    /**
     * Realiza a transformação
     * @throws IUException Exceção em caso de haver modificações incrementais na assinatura com erro
     * @throws IOException
     */
    public abstract void transform() throws IUException, IOException;

    /**
     * Tratamento após realizar a transformação
     * @param exceptions Lista de exceções durante a transformação
     * @param sigCount Quantidade de assinaturas
     */
    public abstract void postTransformation(List<IUException> exceptions, int sigCount);

    /**
     * Retorna o dicionário de referências de uma assinatura
     * @param document O documento assinado
     * @return O dicionário de referências de uma assinatura
     * @throws IOException Exceção em caso de erro na manipulação dos dicionários da assinatura
     */
    public static COSDictionary getSignatureReferenceDictionary(PDDocument document) throws IOException {
        PDSignature firstSignature = document.getSignatureDictionaries().get(0);
        if (firstSignature.getCOSObject().containsKey("Reference")) {
            COSBase item = ((COSArray) firstSignature.getCOSObject().getDictionaryObject("Reference")).get(0);
            if (item instanceof COSObject) {
                item = ((COSObject) item).getObject();
            }
            return (COSDictionary) item;
        }
        return null;
    }

    /**
     * Gera o objeto da transformação
     * @param type Tipo da transformação
     * @param version Versão
     * @param signatureReference Dicionário da assinatura
     * @param document O documento assinado
     * @param previousVersion Versão anterior as transformações do documento
     * @return A transformação
     * @throws IOException Exceção em caso de erro na criação do objeto da transformação
     */
    public static Transformation getTransformation(TransformationType type, float version, COSDictionary signatureReference, PDDocument document, PDDocument previousVersion) throws IOException {
        // A transformação utilizada pode ter comportamento diferentes para diferentes versões do PDF.
        // Não remover parâmetro ainda não utilizado da função.
        if (type == TransformationType.DocMDP) {
            return new DocMDP(signatureReference, document, previousVersion);
        } else if (type == TransformationType.FieldMDP) {
            return new FieldMDPTransformationV16(signatureReference, document, previousVersion);
        }
        throw new IOException(TRANSFORMATION_NOT_FOUND);
    }

    /**
     * Realiza a transformação para todas as assinaturas
     * @param type Tipo da transformação
     * @param document O documento assinado
     * @param content Conteúdo assinado
     * @return Lista de exceções durante a transformação
     * @throws PossibleIncrementalUpdateException Exceção em caso de erro na transformação
     */
    public static List<IUException> transformAll(TransformationType type, PDDocument document, byte[] content) throws PossibleIncrementalUpdateException {
        List<IUException> exceptions = new ArrayList<>();
        PDDocument actualVersion = document;
        PDDocument previousVersion = null;
        float version = document.getVersion();
        int originalDocumentSigCount = 1;
        Transformation transformation = null;

        try {
            actualVersion = PDDocumentUtils.openPDDocument(content);
            COSDictionary signatureReference = getSignatureReferenceDictionary(document);
            PDSignature lastSignature = PDDocumentUtils.getLastSignature(document);
            int[] byteRange = lastSignature.getByteRange();
            originalDocumentSigCount = document.getSignatureDictionaries().size();
            int sigCount = originalDocumentSigCount;
            do {
                previousVersion = PDDocumentUtils.openPDDocument(Arrays.copyOfRange(content, 0, byteRange[2] + byteRange[3]));
                // Use ActualVersion and PreviousVersion
                transformation = getTransformation(type, version, signatureReference, actualVersion, previousVersion);
                try {
                    transformation.transform();
                } catch (IUException e) {
                    exceptions.add(e);
                }
                transformation.postTransformation(exceptions, originalDocumentSigCount);
                // Preparar a próxima transformação
                actualVersion.close();
                actualVersion = previousVersion;
                byteRange = getByteRangeForRemovingLastSignature(actualVersion);
                sigCount--;
            } while (sigCount > 0);
            previousVersion.close();
        } catch (IOException e) {
            PDDocumentUtils.closePDDocument(actualVersion);
            PDDocumentUtils.closePDDocument(previousVersion);
            PossibleIncrementalUpdateException.throwExceptionFromNoVerification(actualVersion);
        }

        return exceptions;
    }

    /**
     * Enumeração de tipos de transformação
     */
    enum TransformationType {
        DocMDP, FieldMDP, UR, Index
    }
}
