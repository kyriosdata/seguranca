package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IUException;
import org.apache.pdfbox.cos.*;

import java.io.IOException;
import java.util.*;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.Action.Path;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.Action.ActionType;
import org.apache.pdfbox.examples.signature.SigUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;

/**
 * Esta classe engloba métodos para a avaliação de objetos em uma assinatura PDF.
 */
public abstract class ObjectEvaluation extends PDDocumentUtils {

    /**
     * O documento assinado na sua versão atual e anterior
     */
    protected PDDocument previousVersion, actualVersion;
    /**
     * Lista de objetos a serem avaliados
     */
    protected List<COSObjectKey> objects;
    /**
     * O catálogo do documento na sua versão atual e anterior
     */
    protected PDDocumentCatalog firstVersionCatalog, actualVersionCatalog;
    /**
     * Valor do parâmetro de transformação
     */
    protected int p;

    /**
     * Construtor
     * @param objects A lista de objetos
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @throws IOException
     */
    public ObjectEvaluation(List<COSObjectKey> objects, PDDocument document, PDDocument previousVersion) throws IOException {
        init(objects, document, previousVersion);
        // Depende da existência do dicionário de permissões no /Catalog.
        // é mais confiável retirar o valor manualmente do /TransformParam e passar ao outro construtor.
        int p = SigUtils.getMDPPermission(document);
        this.p = (p != 0) ? p : 2;
    }

    /**
     * Construtor
     * @param objects A lista de objetos
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @param p Valor do parâmetro de transformação
     * @throws IOException
     */
    public ObjectEvaluation(List<COSObjectKey> objects, PDDocument document, PDDocument previousVersion, int p) throws IOException {
        init(objects, document, previousVersion);
        this.p = p;
    }

    /**
     * Inicializa os atributos da classe
     * @param objects A lista de objetos
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @throws IOException
     */
    void init(List<COSObjectKey> objects, PDDocument document, PDDocument previousVersion) throws IOException {
        this.previousVersion = previousVersion;
        this.actualVersion = document;
        this.firstVersionCatalog = previousVersion.getDocumentCatalog();/// READLY NECESSARY?
        this.actualVersionCatalog = document.getDocumentCatalog();
        this.objects = objects;
    }

    /**
     * Realiza a verificação dos objetos na lista
     * @throws IOException
     * @throws IUException Exceção em caso de haver modificações incrementais na assinatura com erro
     */
    public abstract void evaluate() throws IOException, IUException;

    /**
     *
     * @param dictionary1
     * @param dictionary2
     * @param path
     * @param list
     * @param origin
     * @param visited
     */
    protected void parseDictionary(COSDictionary dictionary1,
                                   COSDictionary dictionary2,
                                   Path path, List<Action> list,
                                   COSObjectKey origin,
                                   Set<COSObjectKey> visited) {
        Iterator<COSName> iterator = dictionary1.keySet().iterator();
        while (iterator.hasNext()) {
            COSName name = iterator.next();
            COSBase a = dictionary1.getItem(name);
            COSBase b = dictionary2.getItem(name);
            path.pushBack(new Action.Path(name, null));
            compare(a, b, path, list, origin, visited);
            path.popBack();
        }
    }

    /**
     *
     * @param a
     * @param b
     * @param path
     * @param list
     * @param origin
     * @param visited
     */
    protected void compare(COSBase a,
                           COSBase b,
                           Path path,
                           List<Action> list,
                           COSObjectKey origin,
                           Set<COSObjectKey> visited) {
        if (a == null) {
            list.add(new Action(ActionType.REMOVED, b, path, origin));
            return;
        } else if (b == null) {
            list.add(new Action(ActionType.INSERTED, a, path, origin));
            return;
        }

        if (a.getClass().equals(b.getClass())) {
            boolean isObject = false;
            if (a instanceof COSObject) {
                isObject = true;
                COSObjectKey key = new COSObjectKey((COSObject) a);
                if (!visited.contains(key)) {
                    visited.add(key);
                    a = ((COSObject) a).getObject();
                    b = ((COSObject) b).getObject();
                } else {
                    return;
                }
            }

            if (a instanceof COSArray) {
                parseArray((COSArray) a, (COSArray) b, path, list, origin, visited);
            } else if (!isObject && a instanceof COSDictionary) {
                    parseDictionary((COSDictionary) a, (COSDictionary) b, path, list, origin, visited);
            } else if (!(a instanceof COSDictionary)) {
                if (!a.equals(b)) {
                    list.add(new Action(ActionType.INSERTED, a, path, origin));
                    list.add(new Action(ActionType.REMOVED, b, path, origin));
                }
            }
        } else {
            if (a instanceof COSObject) {
                COSBase aBase = ((COSObject) a).getObject();
                COSObjectKey key = new COSObjectKey((COSObject) a);
                if (!visited.contains(key)) {
                    visited.add(key);
                    compare(aBase, b, path, list, origin, visited);
                }
            } else if (b instanceof COSObject) {
                COSBase bBase = ((COSObject) b).getObject();
                COSObjectKey key = new COSObjectKey((COSObject) b);
                if (!visited.contains(key)) {
                    visited.add(key);
                    compare(a, bBase, path, list, origin, visited);
                }
            } else {
                list.add(new Action(ActionType.INSERTED, a, path, origin));
                list.add(new Action(ActionType.REMOVED, b, path, origin));
            }
        }
    }

    /**
     *
     * @param array1
     * @param array2
     * @param path
     * @param list
     * @param origin
     * @param visited
     */
    protected void parseArray(COSArray array1,
                              COSArray array2,
                              Path path,
                              List<Action> list,
                              COSObjectKey origin,
                              Set<COSObjectKey> visited) {
        path.pushBack(new Path("Array", null));
        for (int i = 0; i < array1.size(); i++) {
            COSBase base = array1.get(i);
            int index;

            if (base instanceof COSObject) {
                index = findInCOSArray(array2, new COSObjectKey((COSObject) base));
            } else {
                index = findInCOSArray(array2, base);
            }

            if (index == -1) {
                list.add(new Action(ActionType.INSERTED, base, path, origin));
            } else {
                compare(base, array2.get(index), path, list, origin, visited);
            }
        }

        for (int i = 0; i < array2.size(); i++) {
            COSBase base = array2.get(i);
            int index;
            if (base instanceof COSObject) {
                index = findInCOSArray(array1,  new COSObjectKey((COSObject) base));
            } else {
                index = findInCOSArray(array1, base);
            }

            if (index == -1) {
                list.add(new Action(ActionType.REMOVED, base, path, origin));
            } else {
                compare(array1.get(index), base, path, list, origin, visited);
            }
        }
        path.popBack();
    }

    /**
     * Busca a posição do elemento no array
     * @param array O array de objetos
     * @param base O objeto base
     * @return O índice do objeto no array
     */
    protected int findInCOSArray(COSArray array, COSBase base) {
        for (int i = 0; i < array.size(); i++) {
            COSBase item = array.get(i);
            if (isEqual(item, base)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Busca a posição do elemento no array
     * @param array O array de objetos
     * @param object O objeto a ser procurado
     * @return O índice do objeto no array
     */
    protected int findInCOSArray(COSArray array, COSObjectKey object) {
        for (int i = 0; i < array.size(); i++) {
            COSBase item = array.get(i);
            if (item instanceof COSObject && (new COSObjectKey((COSObject) item)).equals(object)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Método de comparação entre dois objetos
     * @param object1 Um objeto a ser comparado
     * @param object2 Outro objeto a ser comparado
     * @return Indica se os objetos são iguais
     */
    protected boolean isEqual(COSObject object1, COSObject object2) {
        List<Action> differences = this.getDifferences(object1, object2);
        return differences.isEmpty();
    }

    protected List<Action> getDifferences(COSObject object1, COSObject object2) {
        COSBase base1 = object1.getObject();
        COSBase base2 = object2.getObject();

        Set<COSObjectKey> visited = new TreeSet<>();
        visited.add(new COSObjectKey(object1));

        List<Action> differences = new ArrayList<>();
        Path path = new Path("Origin", null);
        compare(base1, base2, path, differences, new COSObjectKey(object1), visited);
        return differences;
    }

    /**
     * Método de comparação entre dois objetos
     * @param base1 Um objeto a ser comparado
     * @param base2 Outro objeto a ser comparado
     * @return Indica se os objetos são iguais
     */
    protected boolean isEqual(COSBase base1,COSBase base2) {
        Set<COSObjectKey> visited = new TreeSet<>();

        List<Action> differences = new ArrayList<>();
        Path path = new Path("Origin", null);
        compare(base1, base2, path, differences, null, visited);
        return differences.isEmpty();
    }

    /**
     * Retorna a versão anterior do documento assinado
     * @return A versão anterior do documento assinado
     */
    public PDDocument getFirstVersion() {
        return previousVersion;
    }

    /**
     * Retorna a versão atual do documento assinado
     * @return A versão atual do documento assinado
     */
    public PDDocument getActualVersion() {
        return actualVersion;
    }
}
