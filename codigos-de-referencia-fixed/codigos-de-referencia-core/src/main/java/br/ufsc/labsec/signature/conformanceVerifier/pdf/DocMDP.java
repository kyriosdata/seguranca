package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.DocTimeStampAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IUException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException.ExceptionType;

/**
 * Esta classe é responsável pela validação das persmissões do
 * DocMDP (Document Modification Detection and Prevention).
 */
public class DocMDP extends Transformation {

    /**
     * Lista dos campos MDP
     */
    protected List<COSObjectKey> mdpFields = new ArrayList<>();
    /**
     * Lista dos campos da assinatura
     */
    protected List<COSObjectKey> fieldsAndAnnotations = new ArrayList<>();
    /**
     * O documento assinado na sua versão atual e anterior
     */
    protected PDDocument document, previousVersion;
    /**
     * Bytes do conteúdo da assinatura
     */
    protected byte[] content;
    /**
     * Valor do parâmetro de transformação
     */
    protected int p;
    private static final int DEFAULT_P_VALUE = 2;

    /**
     * Construtor
     * @param signatureReference Dicionário da assinatura
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @param p Valor do parâmetro de transformação
     * @throws IOException
     */
    protected DocMDP(COSDictionary signatureReference, PDDocument document, PDDocument previousVersion, int p) throws IOException {
        this.document = document;
        this.previousVersion = previousVersion;

        COSDictionary transformParams = (COSDictionary) signatureReference.getDictionaryObject("TransformParams");
        this.p = p;
        init(signatureReference, transformParams);
    }

    /**
     * Construtor
     * @param signatureReference Dicionário da assinatura
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @throws IOException
     */
    protected DocMDP(COSDictionary signatureReference, PDDocument document, PDDocument previousVersion) throws IOException {
        this.document = document;
        this.previousVersion = previousVersion;

        COSDictionary transformationParams = (COSDictionary) signatureReference.getDictionaryObject("TransformParams");
        p = (transformationParams.containsKey(COSName.P)) ? transformationParams.getInt(COSName.P) : DEFAULT_P_VALUE;
        init(signatureReference, transformationParams);
    }

    /**
     * Verifica a presença dos campos obrigatórios dependendo da ação no campo MDP
     * @param fieldMDPDictionary Dicionário do MDP
     * @param field Objeto do campo
     * @return Indica se estão presentes todos os campos necessários
     */
    public boolean transformationContainsField(COSDictionary fieldMDPDictionary, COSBase field) {
        return false;
    }

    /**
     * Verifica a quantidade de assinaturas quando o valor do parâmetro de transformação
     * é 1.
     * @throws IOException Exceção em caso de erro durante a manipulação do dicionário
     * @throws IncrementalUpdateException Exceção em caso de haver mais de uma assinatura no documento
     */
    private void verifySignatureCount() throws IOException, IncrementalUpdateException {
        if (this.p == 1) {
            List<PDSignature> signatures = this.document.getSignatureDictionaries();
            int sigCount = 0;
            for (PDSignature signature : signatures) {
                if (!DocTimeStampAttribute.signatureIsTimestamp(signature)) {
                    sigCount++;
                }
            }
            if (sigCount > 1) {
                IncrementalUpdateException.throwExceptionFromSignatureCount(this.document, ExceptionType.GENERATED_FROM_COMPARISON);
            }
        }
    }

    /**
     * Retorna o catálogo do documento
     * @param signatureReference O dicionário da assinatura
     * @return O catálogo do documento
     * @throws IOException Exceção em caso de erro durante a manipulação do dicionário
     */
    protected COSDictionary getCatalog(COSDictionary signatureReference) throws IOException{
        return (COSDictionary) document.getDocument().getCatalog().getObject();
    }

    /**
     * Inicializa os atributos da classe
     * @param signatureReference O dicionário da assinatura
     * @param transformationParams O dicionário dos parâmetros de transformação
     * @throws IOException Exceção em caso de erro durante a manipulação dos dicionários
     */
    private void init(COSDictionary signatureReference, COSDictionary transformationParams) throws IOException {
        List<COSObject> rootObjects = PDDocumentUtils.getRootFieldsFromDocument(document);
        Set<COSObjectKey> previousVersionObjects = this.previousVersion.getDocument().getXrefTable().keySet();
        List<COSObjectKey> allFieldsKey = new ArrayList<>();

        for (COSObject rootObject : rootObjects) {
            allFieldsKey.addAll(PDDocumentUtils.getFieldsFromHierarchy(rootObject));
        }

        for (COSObjectKey key : allFieldsKey) {
            COSObject object = document.getDocument().getObjectFromPool(key);
            /*
                Somente objetos já existentes podem ser verificados pelo FieldMDP,
                enquanto os restantes são verificados pelo DocMDP.
             */
            if (previousVersionObjects.contains(key) &&
                    transformationContainsField(transformationParams, object.getObject())) {
                this.mdpFields.add(key);
            }
            this.fieldsAndAnnotations.add(key);
        }
        List<COSObjectKey> annotations = PDDocumentUtils.getAnnotationsFromDocument(this.document);
        this.fieldsAndAnnotations.addAll(annotations);
    }

    /**
     * Tratamento após realizar a transformação
     * @param exceptions Lista de exceções durante a transformação
     * @param sigCount Quantidade de assinaturas
     */
    @Override
    public void postTransformation(List<IUException> exceptions, int sigCount) { }

    /**
     * Realiza a transformação. Verifica se houveram mudanças no arquivo.
     * @throws IUException Exceção em caso de haver modificações incrementais na assinatura com erro
     */
    @Override
    public void transform() throws IUException, IOException {
        FieldAndAnnotationEvaluation evaluation = new FieldAndAnnotationEvaluation(fieldsAndAnnotations, document, previousVersion, p);
        evaluation.evaluate();
        verifySignatureCount();
    }
}
