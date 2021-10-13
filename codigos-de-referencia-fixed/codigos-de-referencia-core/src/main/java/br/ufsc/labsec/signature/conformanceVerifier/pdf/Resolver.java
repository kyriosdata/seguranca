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
//public abstract class Resolver {
//
//    abstract List<Action> resolve(PDDocument document, PDDocument previous) throws IOException;
//
//    public void parseDictionary(COSDictionary dictionary1, COSDictionary dictionary2, Path path, List<Action> list, COSObject origin) {
//        Iterator<COSName> iterator = dictionary1.keySet().iterator();
//        while (iterator.hasNext()) {
//            COSName name = iterator.next();
//            COSBase a = dictionary1.getItem(name);
//            COSBase b = dictionary2.getItem(name);
//            path.pushBack(new Path(name, null));
//            if (a instanceof COSObject ^ b instanceof COSObject) {
//                list.add(new Action(ActionType.INSERTED, a, path, origin));
//                list.add(new Action(ActionType.REMOVED, b, path, origin));
//            } else {
//                compare(a, b, path, list, origin);
//            }
//            path.popBack();
//        }
//    }
//
//    public void compare(COSBase a, COSBase b, Path path, List<Action> list, COSObject origin) {
//        if (a instanceof COSObject) {
//            return;
//        }
//        if (a.getClass().equals(b.getClass())) {
//            if (a instanceof COSArray) {
//                parseArray((COSArray) a, (COSArray) b, path, list, origin);
//            } else if (a instanceof COSDictionary) {
//                parseDictionary((COSDictionary) a, (COSDictionary) b, path, list, origin);
//            } else {
//                if (!a.equals(b)) {
//                    list.add(new Action(ActionType.INSERTED, a, path, origin));
//                    list.add(new Action(ActionType.REMOVED, b, path, origin));
//                }
//            }
//        } else {
//            list.add(new Action(ActionType.INSERTED, a, path, origin));
//            list.add(new Action(ActionType.REMOVED, b, path, origin));
//        }
//    }
//
//    public void parseArray(COSArray array1, COSArray array2, Path path, List<Action> list, COSObject origin) {
//        path.pushBack(new Path("Array", null));
//        for (int i = 0; i < array1.size(); i++) {
//            COSBase base = array1.get(i);
//            int index;
//
//            if (base instanceof COSObject) {
//                index = findInCOSArray(array2, (COSObject) base);
//            } else {
//                index = findInCOSArray(array2, base);
//            }
//
//            if (index == -1) {
//                list.add(new Action(ActionType.INSERTED, base, path, origin));
//            }
//        }
//
//        for (int i = 0; i < array2.size(); i++) {
//            COSBase base = array2.get(i);
//            int index;
//            if (base instanceof COSObject) {
//                index = findInCOSArray(array1, (COSObject) base);
//            } else {
//                index = findInCOSArray(array2, base);
//            }
//
//            if (index == -1) {
//                list.add(new Action(ActionType.REMOVED, base, path, origin));
//            }
//        }
//        path.popBack();
//    }
//
//    public int findInCOSArray(COSArray array, COSBase base) {
//        for (int i = 0; i < array.size(); i++) {
//            COSBase item = array.get(i);
//            if (item.equals(base)) {
//                return i;
//            }
//        }
//        return -1;
//    }
//
//    public int findInCOSArray(COSArray array, COSObject object) {
//        for (int i = 0; i < array.size(); i++) {
//            COSBase item = array.get(i);
//            if (item instanceof COSObject && (new COSObjectKey((COSObject) item)).equals(new COSObjectKey(object))) {
//                return i;
//            }
//        }
//        return -1;
//    }
//
//    public abstract boolean validatePath(Path path);
//
//    public class Action {
//        private ActionType type;
//        private COSBase base;
//        private Path path;
//        private COSObject origin;
//
//        public Action(ActionType type, COSBase base, Path path, COSObject origin) {
//            this.type = type;
//            this.base = base;
//            this.path = path.clone();
//            this.origin = origin;
//        }
//
//        public Path getPath() {
//            return path;
//        }
//
//        public COSBase getBase() {
//            return base;
//        }
//
//        public ActionType getType() {
//            return type;
//        }
//
//        public COSObject getOrigin() {
//            return origin;
//        }
//    }
//
//    public class Path {
//        private String name;
//        private Path next;
//
//        public Path(COSName name, Path next) {
//            this.name = name.getName();
//            this.next = next;
//        }
//        public Path(String name, Path next) {
//            this.next = next;
//            this.name = name;
//        }
//
//        public void pushBack(Path path) {
//            Path p = this;
//            while (p.next != null) {
//                p = p.next;
//            }
//            p.next = path;
//        }
//
//        public void popBack() {
//            Path p = this;
//            while (p.next != null && p.next.next != null) {
//                p = p.next;
//            }
//
//            if (p.next != null) {
//                p.next = null;
//            }
//        }
//
//        public String getName() {
//            return name;
//        }
//
//        public Path getNext() {
//            return next;
//        }
//
//        public boolean hasNext() {
//            return next != null;
//        }
//
//        @Override
//        public Path clone() {
//            Path cl = new Path(this.name,  null);
//            if (this.next != null) {
//                cl.next = this.next.clone();
//            }
//            return cl;
//        }
//    }
//
//    enum ActionType {
//        REMOVED, INSERTED
//    }
//
//}
