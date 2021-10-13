package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IUException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.PossibleIncrementalUpdateException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.TransformationMethodException;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.*;
import java.util.*;

/**
 * Esta classe auxilia no tratamento de modificações no arquivo PDF.
 */
public class PdfIncrementalUpdatesAuxiliary {

    private static final int DEFAULT_MDP_VALUE = 2;

    /**
     * O documento assinado
     */
    private PDDocument document;
    /**
     * O conteúdo assinado
     */
    private byte[] content;

    /**
     * Construtor
     * @param document O documento assinado
     * @param content O conteúdo assinado
     */
    public PdfIncrementalUpdatesAuxiliary(PDDocument document, byte[] content) {
        this.document = document;
        this.content = content;
    }

    /**
     * Realiza a verificação dos campos e páginas do documento
     * @return A lista de exceções geradas durante a verificação
     */
    public List<IUException> verify() {
        List<IUException> iuExceptions = new ArrayList<>();
        try {
            iuExceptions.addAll(verifyFields());
            iuExceptions.addAll(verifyPages());
        } catch (PossibleIncrementalUpdateException e) {
            // Gerado por erro inesperado na verificação, ao analizar a exceção deve indeterminar todas as assinaturas.
            iuExceptions = new ArrayList<>();
            iuExceptions.add(e);
        }
        Comparator<IUException> comparator = new IUException.Comparator();
        iuExceptions.sort(comparator);
        return iuExceptions;
    }

    /**
     * Realiza a verificação dos campos do documento
     * @return A lista de exceções geradas durante a verificação
     * @throws PossibleIncrementalUpdateException
     */
    private List<IUException> verifyFields() throws PossibleIncrementalUpdateException {
        try {
            try {
                COSDictionary firstSignature = document.getSignatureDictionaries().get(0).getCOSObject();
                if (firstSignature.containsKey("Reference")) {
                    COSArray references = (COSArray) firstSignature.getDictionaryObject("Reference");
                    COSBase item = references.get(0);
                    if (item instanceof COSObject) {
                        item = ((COSObject) item).getObject();
                    }
                    COSDictionary signatureReferenceDictionary = (COSDictionary) item;
                    String method = signatureReferenceDictionary.getNameAsString("TransformMethod");
                    if (method.equals("FieldMDP")) {
                        return Transformation.transformAll(Transformation.TransformationType.FieldMDP, document, content);
                    } else if (method.equals("DocMDP")) {
                        return Transformation.transformAll(Transformation.TransformationType.DocMDP, document, content);
                    } else if (method.equals("UR")) {
                        throw new TransformationMethodException();
                    } else if (method.equals("Identity")) {
                        throw new TransformationMethodException();
                    }
                } else {
                    throw new TransformationMethodException();
                }
            } catch (TransformationMethodException e) {
                //Cant solve transformationMethod
                // Perform basic evaluation
                List<COSObject> rootObjects = PDDocumentUtils.getRootFieldsFromDocument(document);
                List<COSObjectKey> fieldsAndAnnotations = new ArrayList<>();

                for (COSObject rootObject : rootObjects) {
                    fieldsAndAnnotations.addAll(PDDocumentUtils.getFieldsFromHierarchy(rootObject));
                }

                List<COSObjectKey> annotations = PDDocumentUtils.getAnnotationsFromDocument(this.document);
                fieldsAndAnnotations.addAll(annotations);

                FieldAndAnnotationEvaluation.basicEvaluation(fieldsAndAnnotations, document);
            }
        } catch (IOException e) {
            // Unable to evaluate
            PossibleIncrementalUpdateException.throwExceptionFromNoVerification(document);
        }
        return new ArrayList<>();
    }

    /**
     * Busca o objeto 'Pages' na assinatura e realiza a sua verificação
     * @return A lista de exceções geradas durante a verificação
     * @throws PossibleIncrementalUpdateException
     */
    private List<IUException> verifyPages() throws PossibleIncrementalUpdateException {
        boolean supportedVerificationMethod = false;
        try {
            COSDictionary firstSignature = document.getSignatureDictionaries().get(0).getCOSObject();
            if (firstSignature.containsKey("Reference")) {
                COSArray references = (COSArray) firstSignature.getDictionaryObject("Reference");
                COSBase item = references.get(0);
                if (item instanceof COSObject) {
                    item = ((COSObject) item).getObject();
                }
                COSDictionary signatureReferenceDictionary = (COSDictionary) item;
                String method = signatureReferenceDictionary.getNameAsString("TransformMethod");
                if (method.equals("FieldMDP") || method.equals("DocMDP")) {
                    supportedVerificationMethod = true;
                }
            }
        } catch (IOException ignore) {
        }

        List<COSObject> pageObjects = PDDocumentUtils.getPagesFromDocument(document);
        List<COSObjectKey> pages = new ArrayList<>();
        for (COSObject object : pageObjects) {
            pages.add(new COSObjectKey(object));
        }
        return PageEvaluation.evaluateAll(pages, document, content, supportedVerificationMethod);
    }

    /**
     * Busca todos os objetos de página no documento
     * @param treeNode Nodo inicial da busca
     * @param list A lista de objetos de página encontrados
     */
    public void getPagesFromTree(COSDictionary treeNode, List<COSObjectKey> list) {
        COSArray kids = (COSArray) treeNode.getDictionaryObject(COSName.KIDS);
        for (int i = 0; i < kids.size(); i++) {
            COSObject object = (COSObject) kids.get(i);
            COSDictionary dictionary = (COSDictionary) object.getObject();
            if (dictionary.containsKey(COSName.TYPE) && dictionary.getCOSName(COSName.TYPE).equals(COSName.PAGE)) {
                // Objeto de página
                list.add(new COSObjectKey(object));
            } else {
                // Outro nodo da árvore
                getPagesFromTree(dictionary, list);
            }
        }
    }
}
