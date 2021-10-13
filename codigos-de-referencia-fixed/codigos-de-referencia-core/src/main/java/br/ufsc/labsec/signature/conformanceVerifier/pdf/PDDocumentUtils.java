package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.io.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * Esta classe engloba métodos úteis para lidar com modificações
 * no arquivo PDF.
 */
public class PDDocumentUtils {

    private static int DEFAULT_LOOKUP_RANGE = 2048;

    private static Set<String> annotationsSubTypes;
    private static Set<String> fieldEntries;

    static {
        annotationsSubTypes = new HashSet<>();
        annotationsSubTypes.add("Text");
        annotationsSubTypes.add("Link");
        annotationsSubTypes.add("FreeText");
        annotationsSubTypes.add("Line");
        annotationsSubTypes.add("Square");
        annotationsSubTypes.add("Circle");
        annotationsSubTypes.add("Polygon");
        annotationsSubTypes.add("PolyLine");
        annotationsSubTypes.add("Highlight");
        annotationsSubTypes.add("Underline");
        annotationsSubTypes.add("Squiggly");
        annotationsSubTypes.add("StrikeOut");
        annotationsSubTypes.add("Stamp");
        annotationsSubTypes.add("Caret");
        annotationsSubTypes.add("Ink");
        annotationsSubTypes.add("Popup");
        annotationsSubTypes.add("FileAttachment");
        annotationsSubTypes.add("Sound");
        annotationsSubTypes.add("Movie");
        annotationsSubTypes.add("Widget");
        annotationsSubTypes.add("Screen");
        annotationsSubTypes.add("PrinterMark");
        annotationsSubTypes.add("TrapNet");
        annotationsSubTypes.add("Watermark");
        annotationsSubTypes.add("3D");

        fieldEntries = new HashSet<>();
        fieldEntries.add("FT");
        fieldEntries.add("Parent");
        fieldEntries.add("Kids");
        fieldEntries.add("T");
        fieldEntries.add("TU");
        fieldEntries.add("TM");
        fieldEntries.add("Ff");
        fieldEntries.add("V");
        fieldEntries.add("DV");
        fieldEntries.add("AA");
        fieldEntries.add("Opt");
        fieldEntries.add("MaxLen");
        fieldEntries.add("TI");
        fieldEntries.add("I");
        fieldEntries.add("Lock");
        fieldEntries.add("SV");
    }

    /**
     * Retorna o byte range que removerá a última assinatura do documento. Caso o arquivo contenha mais
     * de uma assinatura, será o byterange da penúltima assinatura.
     * @param document O documento assinado
     * @return O byte range de remoção da última assinatura
     * @throws IOException Exceção em caso de erro ao lidar com o dicionário da assinatura
     */
    public static int[] getByteRangeForRemovingLastSignature(PDDocument document) throws IOException {
        List<PDSignature> signatures = document.getSignatureDictionaries();
        int size = signatures.size();
        if (size > 1) {
            PDSignature lastSignature = getLastSignature(document);
            int[] lastSignatureByteRange = lastSignature.getByteRange();
            int[] removeUntil = new int[]{0, 0, 0, 0};
            for (PDSignature sig : signatures) {
                int[] byteRange = sig.getByteRange();
                if (byteRange.length == 4 // Evita IndexOutOfBoundsException
                        && !Arrays.equals(byteRange, lastSignatureByteRange) // Não é a última assinatura
                        && byteRange[2] + byteRange[3] > removeUntil[2] + removeUntil[3]) {
                    removeUntil = byteRange;
                }
            }
            return removeUntil;
        } else {
            return new int[]{0, 0, 0, 0};
        }
    }

    /**
     * Retorna a última assinatura realizada no documento
     * @param document Documento PDF
     * @return A última assinatura do documento
     * @throws IOException Exceção em caso de erro na busca pelas assituras no PDF
     */
    public static PDSignature getLastSignature(PDDocument document) throws IOException {
        PDSignature signature = null;
        int [] byteRange = {0, 0, 0, 0};
        List<PDSignature> signaturesList = document.getSignatureDictionaries();
        for (int i = 0; i < signaturesList.size(); i++) {
            PDSignature sig = signaturesList.get(i);
            int[] sigBr = sig.getByteRange();
            if (byteRange[0] + byteRange[1] < sigBr[0] + sigBr[1]) {
                signature = sig;
                byteRange = sigBr;
            }
        }
        return signature;
    }

    /**
     * Retorna o byte range da primeira assinatura no documento
     * @param document O documento assinado
     * @return O byte range da primeira assinatura
     */
    public static int[] getFirstSignatureByteRange(PDDocument document) {
        try {
            COSDictionary dictionary = document.getSignatureDictionaries().get(0).getCOSObject();
            COSArray byteRange = (COSArray) dictionary.getDictionaryObject(COSName.BYTERANGE);
            return new int[]{
                    byteRange.getInt(0),
                    byteRange.getInt(1),
                    byteRange.getInt(2),
                    byteRange.getInt(3)};
        } catch (IOException e) {
            return new int[]{0, 0, 0, 0};
        }
    }

    /**
     * Retorna o nome do campo
     * @param dictionary O campo de um dicionário
     * @return O nome do campo
     */
    public static String getFullyQualifiedName(COSDictionary dictionary) {
        String parentName = null;
        if (dictionary.containsKey("Parent")) {
            COSBase parent = dictionary.getItem("Parent");
            if (parent instanceof COSObject) {
                parent = ((COSObject) parent).getObject();
            }
            parentName = getFullyQualifiedName((COSDictionary) parent);
        }

        if (dictionary.containsKey("T")) {
            String partialName = dictionary.getString("T");
            return (parentName != null) ? (parentName + "." + partialName) : partialName;
        } else {
            return parentName;
        }
    }

    /**
     * Retorna o endereço do objeto segundo a tabela 'xrefTable'
     * @param document O documeto assindo
     * @param key A chave do objeto procurado
     * @return O endereço do objeto dado
     */
    protected static long retrieveAddress(PDDocument document, COSObjectKey key) {
        Map<COSObjectKey, Long> xrefTable = document.getDocument().getXrefTable();
        long address = xrefTable.get(key);
        if (address < 0) {
            address = xrefTable.get(new COSObjectKey(-address, 0));
        }
        return address;
    }

    public static List<COSObjectKey> getFieldsFromHierarchy(COSObject field) {
        ArrayList<COSObjectKey> list = new ArrayList<>();
        getFieldsHierarchy(field, list);
        return list;
    }

    private static void getFieldsHierarchy(COSObject field, List<COSObjectKey> list) {
        list.add(new COSObjectKey(field));
        COSDictionary dictionary = (COSDictionary) field.getObject();
        COSBase base = dictionary.getItem(COSName.KIDS);
        if (base instanceof COSObject) {
            base = ((COSObject) base).getObject();
        }

        if (base instanceof COSArray) {
            COSArray array = (COSArray) base;
            for (int i = 0; i < array.size(); i++) {
                getFieldsHierarchy((COSObject) array.get(i), list);
            }
        }
    }

    public static List<COSObjectKey> getAnnotationsFromDocument(PDDocument document) {
        List<COSObject> allObjects = document.getDocument().getObjects();
        List<COSObjectKey> annotations = new ArrayList<>();
        for (int i = 0; i < allObjects.size(); i++) {
            COSObject object = allObjects.get(i);
            COSBase base = object.getObject();
            if (base instanceof COSDictionary) {
                COSDictionary dictionary = (COSDictionary) base;
                if (isAnnotation(dictionary)) {
                    annotations.add(new COSObjectKey(
                            object.getObjectNumber(), object.getGenerationNumber()
                    ));
                }
            }
        }
        return annotations;
    }

    public static List<COSObject> getRootFieldsFromDocument(PDDocument document) {
        List<COSObject> allObjects = document.getDocument().getObjects();
        List<COSObject> rootObjects = new ArrayList<>();
        for (int i = 0; i < allObjects.size(); i++) {
            COSObject object = allObjects.get(i);
            COSBase base = object.getObject();
            if (base instanceof COSDictionary) {
                if (((COSDictionary) base).containsKey(COSName.FT)) {
                    rootObjects.add(object);
                }
            }
        }
        return rootObjects;
    }

    public static List<COSObject> getPagesFromDocument(PDDocument document) {
        List<COSObject> allObjects = document.getDocument().getObjects();
        List<COSObject> pageObjects = new ArrayList<>();
        for (int i = 0; i < allObjects.size(); i++) {
            COSObject object = allObjects.get(i);
            COSBase base = object.getObject();
            if (base instanceof COSDictionary) {
                if (((COSDictionary) base).containsKey(COSName.TYPE) &&
                        COSName.PAGE.equals(((COSDictionary) base).getCOSName(COSName.TYPE))) {
                    pageObjects.add(object);
                }
            }
        }
        return pageObjects;
    }

    public static boolean isAnnotation(COSDictionary dictionary) {
        String subType = dictionary.getNameAsString(COSName.SUBTYPE);
        return annotationsSubTypes.contains(subType);
    }

    public static boolean isField(COSDictionary dictionary) {
        COSName fieldType = fieldTypeFromHierarchy(dictionary);
        return fieldType != null;
    }

    public static COSName fieldTypeFromHierarchy(COSDictionary dictionary) {
        COSName fieldType = dictionary.getCOSName(COSName.FT);
        if (fieldType == null && dictionary.containsKey(COSName.PARENT)) {
            COSBase base = dictionary.getDictionaryObject(COSName.PARENT);
            if (base instanceof COSObject) {
                base = ((COSObject) base).getObject();
            }
            if (base instanceof COSDictionary) {
                return fieldTypeFromHierarchy((COSDictionary) base);
            }
        }
        return fieldType;
    }

    public static boolean isFieldEntry(String entry) {
        return fieldEntries.contains(entry);
    }

    public static void closePDDocument(PDDocument document) {
        try {
            if (document != null) {
                document.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static PDDocument openPDDocument(InputStream document) throws IOException {
        byte[] documentBytes = IOUtils.toByteArray(document);
        return openPDDocument(documentBytes);
    }

    public static PDDocument openPDDocument(byte[] documentBytes) throws IOException {
        RandomAccessRead source = new RandomAccessBuffer(documentBytes);
        ConfiguredPDFParser parser = new ConfiguredPDFParser(source);

        /*
         * A chamada de "containsEOFInRange" resulta em duas buscas pelo símbolo EOF, contudo, mantém o uso da biblioteca
         * intácto, permitindo modificações na dependência do PDFBox sem quebrar o funcionamento.
         */
        if (parser.containsEOFInRange(DEFAULT_LOOKUP_RANGE)) {
            parser.setEOFLookupRange(DEFAULT_LOOKUP_RANGE);
            parser.parse();
        } else if (documentBytes.length > DEFAULT_LOOKUP_RANGE *2) {
            /*
             * Quanto temos certeza que vamos encontrar o EOF, o valor padrão de lenient igual a true NÃO se torna um
             * problema. Porém, aqui, quando realiza-se um chute de encontrar o EOF em uma metade do arquivo,
             * deve-se desabilitar o lenient, pois um chute incorreto resultará na leitura errada dos valores presentes
             * na table XREF, impedindo a verificação de atualizações incrementais.
             */
            parser.setEOFLookupRange(documentBytes.length / 2);
            parser.setLenient(false);
            parser.parse();
        } else {
            throw new IOException();
        }
        return parser.getPDDocument();
    }
}
