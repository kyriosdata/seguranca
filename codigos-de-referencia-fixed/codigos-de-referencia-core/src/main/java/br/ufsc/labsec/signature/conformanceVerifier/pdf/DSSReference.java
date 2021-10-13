package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.io.RandomAccessBufferedFileInputStream;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

/**
 * Esta classe engloba métodos que lidam com a referência DSS
 * de uma assinatura PDF.
 */
public class DSSReference {

    /**
     * A tabela xref do PDF
     */
    private Map<COSObjectKey, Long> xrefTable;
    /**
     * Conjunto de endereços apontados na tabela xref
     */
    private Set<Long> addresses;
    /**
     * O conteúdo assinado
     */
    private byte[] content;
    /**
     * O documento assinado
     */
    private PDDocument document;

    /**
     * Construtor
     * @param dssObject O objeto DSS
     * @param xrefTable A tabela xref do PDF
     * @param content O conteúdo assinado
     * @param document O documento assinado
     */
    public DSSReference(COSObject dssObject, Map<COSObjectKey, Long> xrefTable, byte[] content, PDDocument document) {
        this.xrefTable = xrefTable;
        this.content = content;
        this.document = document;
        addresses = new HashSet<Long>();
        long objAddress = xrefTable.get(new COSObjectKey(dssObject));
        addresses.add(objAddress);
        parseNext(dssObject.getObject(), objAddress);
    }

    private final long NO_OBJECT_ADDRESS = -1;

    /**
     * Realiza a operação de parse no dicionário
     * @param dictionary O dicionário
     * @param objectAddress O endereço do objeto
     */
    protected void parseDictionary(COSDictionary dictionary, long objectAddress) {
        Iterator<COSName> iterator = dictionary.keySet().iterator();

        while (iterator.hasNext()) {
            COSName key = iterator.next();
            COSBase base = dictionary.getItem(key);
            long objAddress = NO_OBJECT_ADDRESS;
            if (base instanceof COSObject) {
                COSObject object = (COSObject) base;
                long address = xrefTable.get(new COSObjectKey(object));
                addresses.add(address);
                objAddress = address;
                base = object.getObject();
            }

            parseNext(base, objAddress);
        }
    }

    /**
     * Verifica o tipo do próximo elemento no dicionário e
     * chama o método de parse adequado
     * @param base O objeto base
     * @param objectAddress O endereço do objeto
     */
    private void parseNext(COSBase base, long objectAddress) {
        if (base instanceof COSStream) {
            parseStream((COSStream) base, objectAddress);
        } else if (base instanceof COSDictionary) {
            parseDictionary((COSDictionary) base, objectAddress);
        } else if (base instanceof COSArray) {
            parseArray((COSArray) base, objectAddress);
        }
    }

    /**
     * Realiza a operação de parse no elemento do tipo array
     * @param array O objeto array
     * @param objectAddress O endereço do objeto
     */
    protected void parseArray(COSArray array, long objectAddress) {
        for (int i = 0; i < array.size(); i++) {
            COSBase base = array.get(i);
            long objAddress = NO_OBJECT_ADDRESS;
            if (base instanceof COSObject) {
                COSObject object = (COSObject) base;
                long address = xrefTable.get(new COSObjectKey(object));
                addresses.add(address);
                objAddress = address;
                base = object.getObject();
            }

            parseNext(base, objAddress);
        }
    }

    /**
     * Realiza a operação de parse no elemento do tipo stream
     * @param stream O objeto stream
     * @param objectAddress O endereço do objeto
     */
    protected void parseStream(COSStream stream, long objectAddress) {
        try {
            byte[] lengthDictionary = Arrays.copyOfRange(content, (int)objectAddress, content.length);
            StreamLengthResolver streamLengthResolver = new StreamLengthResolver(
                    new RandomAccessBufferedFileInputStream(new ByteArrayInputStream(lengthDictionary)), document);
            COSObject lengthObject = streamLengthResolver.getLengthObject();
            if (lengthObject != null) {
                long lengthAddress = xrefTable.get(new COSObjectKey(lengthObject));
                addresses.add(lengthAddress);
            }
        } catch (IOException e) { }
    }

    /**
     * Verifica se o conjunto de endereços contém o endereço dado
     * @param address O endereço cuja presença será verificada
     * @return Indica se o conjunto de endereços contém o endereço dado
     */
    public boolean containsAddress(long address) {
        return addresses.contains(address);
    }

    /**
     * Esta classe lida com o objeto 'Length' em um dicionário PDF
     */
    private class StreamLengthResolver extends DictionaryParser {

        /**
         * Um dicionário de um documento PDF
         */
        private COSDictionary dictionary;

        /**
         * Construtor
         * @param source Objeto que permite leitura aleatório em um documento
         * @param document O documento PDF
         */
        public StreamLengthResolver(RandomAccessRead source, PDDocument document) {
            super(source, document);
        }

        /**
         * Retorna o objeto 'Length' do dicionário
         * @return O objeto 'Length' do dicionário
         * @throws IOException Exceção em caso de erro na manipulação do dicionário
         */
        public COSObject getLengthObject() throws IOException {
            /*
            Somente percorre um único dicionário
             */
            if (dictionary == null) {
                dictionary = this.parseDictionary();
            }

            if (dictionary.containsKey("Length")) {
                COSBase base = dictionary.getItem("Length");
                if (base instanceof COSObject) {
                    return (COSObject) base;
                }
            }

            return null;
        }
    }
}
