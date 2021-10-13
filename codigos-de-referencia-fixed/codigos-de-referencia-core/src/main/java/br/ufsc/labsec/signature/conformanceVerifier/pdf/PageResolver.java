//package br.ufsc.labsec.signature.conformanceVerifier.pdf;
//
//import org.apache.pdfbox.cos.*;
//import org.apache.pdfbox.pdmodel.PDDocument;
//
//import java.io.IOException;
//import java.util.ArrayList;
//import java.util.Iterator;
//import java.util.List;
//
//public class PageResolver extends Resolver {
//
//    private List<COSObjectKey> signatureObjects;
//
//    public PageResolver(List<COSObjectKey> signatureObjects) {
//        this.signatureObjects = signatureObjects;
//    }
//
//    @Override
//    public List<Action> resolve(PDDocument actual, PDDocument previous) throws IOException {
//        ArrayList<Action> differences = new ArrayList<>();
//        List<COSObject> pages = actual.getDocument().getObjectsByType("Page");
//        Iterator<COSObject> iterator = pages.iterator();
//        Path path = new Path("Origin", null);
//        while (iterator.hasNext()) {
//            COSObject actualObject = iterator.next();
//            COSObject previousObject = previous.getDocument().getObjectFromPool(new COSObjectKey(actualObject));
//            if (previousObject != null) {
//                parseDictionary((COSDictionary) actualObject.getObject(), (COSDictionary) previousObject.getObject(), path, differences, actualObject);
//            } else {
//                differences.add(new Action(ActionType.INSERTED, actualObject, path, actualObject));
//            }
//        }
//
//        // Remove-se as alterações inválidas, deixando somente as alteraçações válidas para
//        // serem futuramente desconsideradas.
//        for (Action difference : differences) {
//            if (validatePath(difference.getPath()) && difference.getType() == ActionType.INSERTED) {
//                COSBase base = difference.getBase();
//                if (!(base instanceof COSObject && signatureObjects.contains(new COSObjectKey((COSObject) base)))) {
//                    differences.remove(difference);
//                }
//            } else {
//                differences.remove(difference);
//            }
//        }
//        return differences;
//    }
//
//    @Override
//    public boolean validatePath(Path path) {
//        String[][] validPath = {{"Origin", "Annots"}, {"Origin", "Annots", "Array"}};
//        boolean valid = false;
//        for (int i = 0; i < validPath.length; i++) {
//            Path p = path;
//            int index = 0;
//            boolean v = true;
//            while (index < validPath[i].length && p != null) {
//                if (!validPath[i][index++].equals(p.getName())) {
//                    v = false;
//                    break;
//                }
//                p = p.getNext();
//            }
//            v = v && p == null && index == validPath[i].length;
//            valid = valid || v;
//        }
//        return valid;
//    }
//
//}
