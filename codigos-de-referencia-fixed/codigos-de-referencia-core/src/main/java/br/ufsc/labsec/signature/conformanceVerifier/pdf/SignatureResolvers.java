//package br.ufsc.labsec.signature.conformanceVerifier.pdf;
//
//import br.ufsc.labsec.signature.conformanceVerifier.pdf.Resolver.Action;
//import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
//import org.apache.pdfbox.cos.COSArray;
//import org.apache.pdfbox.cos.COSDictionary;
//import org.apache.pdfbox.cos.COSObject;
//import org.apache.pdfbox.cos.COSObjectKey;
//import org.apache.pdfbox.pdmodel.PDDocument;
//import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
//import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
//
//import java.io.IOException;
//import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.List;
//import java.util.Map;
//
//public class SignatureResolvers {
//    private Resolver resolvers[];
//    private PDDocument document;
//    private byte[] content;
//    private ArrayList<COSObjectKey> signatureObjects;
//    private List<Long> incrementalReferences;
//
//    public SignatureResolvers(PDDocument document, byte[] content, List<Long> incrementalReferences) {
//        this.document = document;
//        this.content = content;
//        this.incrementalReferences = incrementalReferences;
//        signatureObjects = new ArrayList<>();
//        COSArray fields = (COSArray) document.getDocumentCatalog().getAcroForm().getCOSObject().getItem("Fields");
//        for (int i = 0; i < fields.size(); i++) {
//            signatureObjects.add(new COSObjectKey((COSObject) fields.get(i)));
//        }
//        resolvers = new Resolver[]{new PageResolver(signatureObjects)};
//    }
//
//    public void resolveAll() throws IOException {
//        PDDocument actual = document;
//        PDDocument previous;
//        List<PDSignature> signatureList = actual.getSignatureDictionaries();
//        int previousIndex = 1;
//        int signatureIndex = signatureList.size();
//        ArrayList<COSObjectKey> validUpdatedObjects = new ArrayList<>();
//        while (previousIndex == 1 || signatureList.size() > 1) {
//            PDSignature lastSignature = signatureList.get(signatureList.size() - previousIndex);
//            int[] byteRange = lastSignature.getByteRange();
//            previous = PDDocument.load(Arrays.copyOfRange(content, byteRange[0], byteRange[2] + byteRange[3]));
//            for (int i = 0; i < resolvers.length; i++) {
//                List<Action> actions = resolvers[i].resolve(actual, previous);
//                for (int j = 0; j < actions.size(); j++) {
//                    validUpdatedObjects.add(new COSObjectKey( actions.get(j).getOrigin()));
//                }
//            }
//            actual = previous;
//            signatureIndex -= previousIndex - 1;
//            signatureList = actual.getSignatureDictionaries();
//            previousIndex = 2;
//        }
//        Map<COSObjectKey, Long> xrefTable = document.getDocument().getXrefTable();
//        for (int i = 0; i < validUpdatedObjects.size(); i++) {
//            incrementalReferences.remove(xrefTable.get(validUpdatedObjects.get(i)));
//        }
//    }
//}
