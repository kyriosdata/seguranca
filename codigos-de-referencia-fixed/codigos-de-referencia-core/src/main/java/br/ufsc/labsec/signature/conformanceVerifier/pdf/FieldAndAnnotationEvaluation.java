package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IUException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.PossibleIncrementalUpdateException;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.IOException;
import java.util.*;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.Action.Path;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException.ExceptionType;

/**
 * Esta classe engloba métodos para a avaliação de um campo e anotação (widget) em documentos pdf assinados
 */
public class FieldAndAnnotationEvaluation extends ObjectEvaluation {

    /**
     * Lista de campos e antoações
     */
    private List<COSObjectKey> fieldsAndAnnotations;

    /**
     * Construtor
     * @param fieldsAndAnnotations A lista de campos
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @throws IOException
     */
    public FieldAndAnnotationEvaluation(List<COSObjectKey> fieldsAndAnnotations, PDDocument document, PDDocument previousVersion) throws IOException {
        super(fieldsAndAnnotations, document, previousVersion);
        this.fieldsAndAnnotations = this.objects;
    }

    /**
     * Construtor
     * @param fieldsAndAnnotations A lista de campos
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @param p Índice do parâmetro de transformação
     * @throws IOException
     */
    public FieldAndAnnotationEvaluation(List<COSObjectKey> fieldsAndAnnotations, PDDocument document, PDDocument previousVersion, int p) throws IOException {
        super(fieldsAndAnnotations, document, previousVersion, p);
        this.fieldsAndAnnotations = this.objects;
    }

    /**
     * Realiza a verificação dos campos na lista
     * @throws IOException
     * @throws IncrementalUpdateException
     */
    @Override
    public void evaluate() throws IOException, IUException {
        List<Action> differences = new ArrayList<>();
        Path path = new Path("Origin", null);
        Set<COSObjectKey> visited = new TreeSet<>();

        for (int i = 0; i < fieldsAndAnnotations.size(); i++) {
            visited.add(fieldsAndAnnotations.get(i));
            COSObject object1 = actualVersion.getDocument().getObjectFromPool(fieldsAndAnnotations.get(i));
            COSObject object2 = previousVersion.getDocument().getObjectFromPool(fieldsAndAnnotations.get(i));
            compare(object1.getObject(), object2.getObject(), path, differences, fieldsAndAnnotations.get(i), visited);
            visited.clear();
        }

        Set<Result> acceptedResults = new HashSet<>();
        switch (p) {
            case 3:
                acceptedResults.add(Result.INSERTED_ANNOT);
                acceptedResults.add(Result.REMOVED_ANNOT);
                acceptedResults.add(Result.ALTERED_ANNOT);
            case 2:
                acceptedResults.add(Result.FILLED_FORM);
                acceptedResults.add(Result.ALTERED_MODIFICATION_DATE);
                acceptedResults.add(Result.INSERTED_SIG_FIELD);
            case 1:
        }

        for (int i = 0; i < differences.size(); i++) {
            Result result = evaluateAction(differences.get(i));
            if (!acceptedResults.contains(result)) {
                IncrementalUpdateException.throwExceptionFromModification(
                        previousVersion, result.getMessage(), ExceptionType.GENERATED_FROM_COMPARISON);
            }
        }
    }

    /**
     * Realiza uma avaliação simples dos campos. Utilizado quando ocorre erro
     * com o método de transformação
     * @param fieldsAndAnnotations A lista de campos
     * @param document O documento assinado
     * @throws IOException
     * @throws PossibleIncrementalUpdateException
     */
    public static void basicEvaluation(List<COSObjectKey> fieldsAndAnnotations, PDDocument document) throws IOException, PossibleIncrementalUpdateException {
        int [] byteRange = getFirstSignatureByteRange(document);
        for (int i = 0; i < fieldsAndAnnotations.size(); i++) {
            COSObjectKey key = fieldsAndAnnotations.get(i);
            COSDictionary object = (COSDictionary) document.getDocument().getObjectFromPool(key).getObject();
            long address = retrieveAddress(document, key);
            COSName fieldType = object.getCOSName(COSName.FT);
            if (PDDocumentUtils.isField(object) && COSName.SIG.equals(fieldType)) {
                int[] sigByteRange;
                if (object.containsKey(COSName.V)) {
                    // Check if signature field is protected its referenced signature.
                    COSDictionary signature = (COSDictionary) object.getDictionaryObject(COSName.V);
                    COSArray array = (COSArray) signature.getDictionaryObject(COSName.BYTERANGE);
                    sigByteRange = new int[]{array.getInt(0), array.getInt(1), array.getInt(2), array.getInt(3)};
                } else {
                    // Check if empty signature field is protected by at least one signature.
                    sigByteRange = PDDocumentUtils.getLastSignature(document).getByteRange();
                }
                if (!(address >= sigByteRange[0] && address <= sigByteRange[2] + sigByteRange[3])) {
                    // todo Which signature generated the exception can be found, should not invalidate all
                    PossibleIncrementalUpdateException.throwExceptionFromModification(Result.INSERTED_SIG_FIELD.getMessage(), document);
                }
            } else if (address < byteRange[0] || address > byteRange[2] + byteRange[3]) {
                PossibleIncrementalUpdateException.throwExceptionFromModification(Result.OTHER.getMessage(), document);
            }
        }
    }

    /**
     * Verifica uma ação
     * @param action A ação a ser avaliada
     * @return O resultado da avaliação
     * @throws IOException
     */
    public Result evaluateAction(Action action) throws IOException {
        Path path = action.getPath();
        int pathSize = path.getSize();

        COSObject object = actualVersion.getDocument().getObjectFromPool(action.getOrigin());
        COSDictionary dictionary = (COSDictionary) object.getObject();
        COSName fieldType = PDDocumentUtils.fieldTypeFromHierarchy(dictionary);
        boolean isField = fieldType != null;
        boolean isAnnot = PDDocumentUtils.isAnnotation(dictionary);

        if (pathSize == 1) {
            // Um objeto foi adicionado ou deletado por completo
            if (COSName.SIG.equals(fieldType)) {
                // Field de uma assinatura
                if (action.getType() == Action.ActionType.INSERTED) {
                    return Result.INSERTED_SIG_FIELD;
                } else {
                    return Result.REMOVED_SIG_FIELD;
                }
            } else if (isField) {
                // Um Field qualquer
                if (action.getType() == Action.ActionType.INSERTED) {
                    return Result.INSERTED_FIELD;
                } else {
                    return Result.REMOVED_FIELD;
                }
            } else if (isAnnot){
                // Uma anotação
                if (action.getType() == Action.ActionType.INSERTED) {
                    return Result.INSERTED_ANNOT;
                } else {
                    return Result.REMOVED_ANNOT;
                }
            }
        } else if (path.getNext() != null) {
            String entry = path.getNext().getName();
            if (entry.equals("M")) {
                return Result.ALTERED_MODIFICATION_DATE;
            } else if (isField && isAnnot) {
                if (entry.equals("V")) {
                    return Result.FILLED_FORM;
                } else if (PDDocumentUtils.isFieldEntry(entry)) {
                    return Result.ALTERED_FIELD;
                } else {
                    return Result.ALTERED_ANNOT;
                }
            } else if (isField) {
                if (entry.equals("V")) {
                    return Result.FILLED_FORM;
                } else if (PDDocumentUtils.isAnnotation(dictionary)) {
                    return Result.ALTERED_FIELD;
                }
            } else if (isAnnot) {
                return Result.ALTERED_ANNOT;
            }
        }
        return Result.OTHER;
    }

    /**
     * Enumeração dos resultados de uma avaliação de campo
     */
    enum Result {
        FILLED_FORM,
        INSERTED_SIG_FIELD, REMOVED_SIG_FIELD,
        INSERTED_ANNOT, REMOVED_ANNOT, ALTERED_ANNOT,
        INSERTED_FIELD, REMOVED_FIELD, ALTERED_FIELD,
        OTHER, ALTERED_MODIFICATION_DATE;
        public String getMessage() {
            switch (this) {
                case FILLED_FORM:
                    return "formulário preenchido";
                case INSERTED_SIG_FIELD:
                    return "campo de assinatura inserido";
                case REMOVED_SIG_FIELD:
                    return "campo de assinatura removido";
                case INSERTED_ANNOT:
                    return "anotação inserida";
                case REMOVED_ANNOT:
                    return "anotação removida";
                case ALTERED_ANNOT:
                    return "anotação alterada";
                case INSERTED_FIELD:
                    return "formulário inserido";
                case REMOVED_FIELD:
                    return "formulário removido";
                case ALTERED_FIELD:
                    return "estrutura do formulário modificado";
                case ALTERED_MODIFICATION_DATE:
                    return "data de modificação alterada";
                default:
                    return "modificação";
            }
        }
    }
}
