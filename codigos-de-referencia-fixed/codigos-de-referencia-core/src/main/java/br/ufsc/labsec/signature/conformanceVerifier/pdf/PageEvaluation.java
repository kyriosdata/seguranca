package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IUException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.PossibleIncrementalUpdateException;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;
import java.util.*;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.Action.Path;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException.ExceptionType;

/**
 * Esta classe engloba métodos para a avaliação de uma página
 * de uma assinatura PDF.
 */
public class PageEvaluation extends ObjectEvaluation{

    /**
     * A lista de páginas do arquivo
     */
    private List<COSObjectKey> pages;
    /**
     * Indica se há valores de MDP na assinatura
     */
    private boolean mdp;

    /**
     * Construtor
     * @param pages A lista de páginas do arquivo
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @param mdp Indica se há valores de MDP na assinatura
     * @throws IOException
     */
    public PageEvaluation(List<COSObjectKey> pages, PDDocument document, PDDocument previousVersion, boolean mdp) throws IOException {
        super(pages, document, previousVersion);
        this.pages = this.objects;
        this.mdp = mdp;
    }

    /**
     * Construtor
     * @param fields A lista de páginas do arquivo
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @param p Índice do parâmetro de transformação
     * @throws IOException
     */
    public PageEvaluation(List<COSObjectKey> fields, PDDocument document, PDDocument previousVersion, int p) throws IOException {
        super(fields, document, previousVersion, p);
        this.pages = this.objects;
        this.mdp = true;
    }

    /**
     * Realiza a verificação das páginas na lista
     * @throws IOException
     * @throws IncrementalUpdateException
     */
    @Override
    public void evaluate() throws IOException, IUException {
        Set<Result> acceptedResults = new HashSet<>();
        if (!mdp) {
            acceptedResults.add(Result.INSERTED_SIGNATURE_ANNOT);
            acceptedResults.add(Result.INSERTED_SIGNATURE_ANNOT_ARRAY);
        } else {
            switch (p) {
                case 3:
                case 2:
                    acceptedResults.add(Result.REMOVED_TEMPLATE_TYPE);
                    acceptedResults.add(Result.INSERTED_PAGE_TYPE);
                case 1:
                    acceptedResults.add(Result.INSERTED_SIGNATURE_ANNOT);
                    acceptedResults.add(Result.INSERTED_SIGNATURE_ANNOT_ARRAY);
            }
        }

        COSDictionary nameDictionary = new COSDictionary();
        if (actualVersion.getDocumentCatalog().getNames() != null) {
            nameDictionary = (COSDictionary) actualVersion.getDocumentCatalog().getNames().getCOSObject().getDictionaryObject(COSName.PAGES);
        }
        Set<COSObjectKey> visited = new TreeSet<>();
        for (int i = 0; i < pages.size(); i++) {
            COSObjectKey key = pages.get(i);
            COSDictionary pageObject = (COSDictionary) actualVersion.getDocument().getObjectFromPool(key).getObject();
            COSDictionary previousObject;
            if (pageObject.containsKey("TemplateInstantiated")) { // Originated from template, find template
                String templateInstantiated = pageObject.getNameAsString("TemplateInstantiated");
                previousObject = (COSDictionary) nameDictionary.getDictionaryObject(templateInstantiated);
            } else { // Already existed
                previousObject = (COSDictionary) previousVersion.getDocument().getObjectFromPool(key).getObject();
            }
            visited.add(pages.get(i));
            List<Action> differences = new ArrayList<>();
            Path path = new Path("Page", null);
            compare(pageObject, previousObject, path, differences, key, visited);
            visited.clear();
            for (int j = 0; j < differences.size(); j++) {
                Result result = evaluateAction(differences.get(j));
                if (!acceptedResults.contains(result)) {
                    if (mdp) {
                        IncrementalUpdateException.throwExceptionFromModification(previousVersion, result.getMessage(), ExceptionType.GENERATED_FROM_COMPARISON);
                    } else {
                        PossibleIncrementalUpdateException.throwExceptionFromModification(result.getMessage(), previousVersion);
                    }
                }
            }
        }
    }

    /**
     * Avalia uma ação
     * @param action A ação a ser avaliada
     * @return O resultado da avaliação
     */
    public Result evaluateAction(Action action) {
        Path path = action.getPath();

        if (path.getNext() != null && path.getNext().getName().equals(COSName.TYPE.toString())) {
            if (action.getBase() instanceof COSName) {
                COSName type = (COSName) action.getBase();
                if (action.getType() == Action.ActionType.INSERTED && type.equals(COSName.PAGE)) {
                    return Result.INSERTED_PAGE_TYPE;
                } else if (action.getType() == Action.ActionType.REMOVED && type.equals(COSName.TEMPLATES)) {
                    return Result.REMOVED_TEMPLATE_TYPE;
                } else {
                    return Result.OTHER;
                }
            } else {
                return Result.OTHER;
            }
        }

        if (action.getType() == Action.ActionType.INSERTED && // Action was a insertion
                path.getNext() != null && path.getNext().getName().equals("Annots")) { //  Was inserted in Annots array
            COSBase object = action.getBase();
            if (object instanceof COSObject) {
                object = ((COSObject) object).getObject();
            }
            if (path.getNext().getNext() != null && path.getNext().getNext().getName().equals("Array")) { // Avaliando dentro do array
                COSBase insertedObject = object;
                if (insertedObject instanceof COSObject) {
                    insertedObject = ((COSObject) insertedObject).getObject();
                }
                if (isSigFieldAnnotation((COSDictionary) insertedObject)) { // Is annotation
                    return Result.INSERTED_SIGNATURE_ANNOT;
                } else {
                    return Result.OTHER;
                }
            } else {
                COSArray array = (COSArray) object;
                for (int i = 0; i < array.size(); i++) {
                    COSBase insertedObject = array.get(i);
                    if (insertedObject instanceof COSObject) {
                        insertedObject = ((COSObject) insertedObject).getObject();
                    }
                    if (!isSigFieldAnnotation((COSDictionary) insertedObject)) {
                        return Result.OTHER;
                    }
                }
                return Result.INSERTED_SIGNATURE_ANNOT_ARRAY;
            }
        }
        return Result.OTHER;
    }

    /**
     * Verifica se o campo em um dicionário annotation é do tipo 'Sig'
     * @param dictionary O dicionário a ser verificado
     * @return Indica se o campo no dicionário é do tipo 'Sig'
     */
    private boolean isSigFieldAnnotation(COSDictionary dictionary) {
        // Type entry is optional if it is possible to identify the type of the dictionary without its presence.
        // Because for widget annotations, the subtype entry equals to "Widget" is mandatory, it is a valid identification
        // of an annotation.
        // TODO - This function should be updated with implicit definition of other annotations subtypes in the future.
        if (dictionary.containsKey(COSName.FT) && // Is field dictionary
                (hasAnnotType(dictionary) || isWidgetAnnotation(dictionary))) {
            COSName fieldType = dictionary.getCOSName(COSName.FT);
            return fieldType.equals(COSName.SIG);
        }
        return false;
    }

    /**
     * Verifica se o tipo do campo é 'ANNOT'
     * @param dictionary Os valores do campo
     * @return Indica se o tipo do campo é 'ANNOT'
     */
    private boolean hasAnnotType(COSDictionary dictionary) {
        return dictionary.containsKey(COSName.TYPE) &&
                dictionary.getCOSName(COSName.TYPE) == COSName.ANNOT;
    }

    /**
     * Verifica se o subtipo do campo é 'WIDGET'
     * @param dictionary Os valores do campo
     * @return Indica se o subtipo do campo é 'WIDGET'
     */
    private boolean hasWidgetSubtype(COSDictionary dictionary) {
        return dictionary.containsKey(COSName.SUBTYPE) &&
                dictionary.getCOSName(COSName.SUBTYPE).equals(COSName.WIDGET);
    }

    /**
     * Verifica se o campo é 'WIDGET'
     * @param dictionary Os valores do campo
     * @return Indica se o subtipo do campo é 'WIDGET'
     */
    private boolean isWidgetAnnotation(COSDictionary dictionary) {
        return hasWidgetSubtype(dictionary);
    }

    /**
     * Enumeração dos resultados de uma avaliação de página
     */
    enum Result {
        INSERTED_SIGNATURE_ANNOT, INSERTED_SIGNATURE_ANNOT_ARRAY, OTHER, REMOVED_TEMPLATE_TYPE, INSERTED_PAGE_TYPE;
        public String getMessage() {
            switch (this) {
                case INSERTED_SIGNATURE_ANNOT:
                case INSERTED_SIGNATURE_ANNOT_ARRAY:
                    return "alteração das referências de anotações em objeto de página";
                case REMOVED_TEMPLATE_TYPE:
                case INSERTED_PAGE_TYPE:
                    return "instanciação de página";
                default:
                    return "modificação";
            }
        }
    }

    /**
     * Avalia todas as páginas da lista
     * @param pages A lista de páginas do arquivo
     * @param document O documento assinado
     * @param content O conteúdo assinado
     * @param mdp Indica se há valores de MDP na assinatura
     * @return A lista de exceções que ocorreram durante a avaliação
     * @throws PossibleIncrementalUpdateException
     */
    public static List<IUException> evaluateAll(List<COSObjectKey> pages, PDDocument document, byte[] content, boolean mdp) throws PossibleIncrementalUpdateException {
        List<IUException> exceptions = new ArrayList<>();
        PDDocument actualVersion, previousVersion;
        actualVersion = document;
        previousVersion = null;
        try {
            PDSignature lastSignature = PDDocumentUtils.getLastSignature(document);
            int[] byteRange = lastSignature.getByteRange();
            int sigCount = document.getSignatureDictionaries().size();
            do {
                previousVersion = PDDocumentUtils.openPDDocument(Arrays.copyOfRange(content, 0, byteRange[2] + byteRange[3]));
                // Use ActualVersion and PreviousVersion
                PageEvaluation evaluation = new PageEvaluation(pages, actualVersion, previousVersion, mdp);
                try {
                    evaluation.evaluate();
                } catch (IUException e) {
                    exceptions.add(e);
                }
                actualVersion.close();
                actualVersion = previousVersion;
                byteRange = getByteRangeForRemovingLastSignature(actualVersion);
                sigCount--;
            } while (sigCount > 0);
            previousVersion.close();
        } catch (IOException e) {
            PDDocumentUtils.closePDDocument(actualVersion);
            PDDocumentUtils.closePDDocument(previousVersion);
            PossibleIncrementalUpdateException.throwExceptionFromNoVerification(document);
        }
        return exceptions;
    }
}
