package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSObjectKey;

/**
 * Esta classe representa uma ação no dicionário MDP.
 */
public class Action {
    /**
     * Tipo da ação
     */
    private ActionType type;
    /**
     * Objeto base no documento
     */
    private COSBase base;
    /**
     * Caminho do objeto
     */
    private Path path;
    /**
     * Chave que referencia o objeto
     */
    private COSObjectKey origin;

    /**
     * Construtor
     * @param type Tipo da ação
     * @param base Objeto base no documento
     * @param path Caminho do objeto
     * @param origin Chave que referencia o objeto
     */
    public Action(ActionType type, COSBase base, Path path, COSObjectKey origin) {
        this.type = type;
        this.base = base;
        this.path = path.clone();
        this.origin = origin;
    }

    /**
     * Retorna o caminho do objeto
     * @return O caminho do objeto
     */
    public Path getPath() {
        return path;
    }

    /**
     * Retorna o objeto base no documento
     * @return O objeto base no documento
     */
    public COSBase getBase() {
        return base;
    }

    /**
     * Retorna o tipo da ação
     * @return O tipo da ação
     */
    public ActionType getType() {
        return type;
    }

    /**
     * Retorna a chave que referencia o objeto
     * @return A chave que referencia o objeto
     */
    public COSObjectKey getOrigin() {
        return origin;
    }

    /**
     * Esta classe representa um caminho
     */
    static class Path {
        /**
         * Nome do caminho
         */
        private String name;
        /**
         * Caminho do próximo objeto
         */
        private Path next;

        /**
         * Construtor
         * @param name Nome do caminho
         * @param next Caminho do próximo objeto
         */
        public Path(COSName name, Path next) {
            this.name = name.getName();
            this.next = next;
        }

        /**
         * Construtor
         * @param name Nome do caminho
         * @param next Caminho do próximo objeto
         */
        public Path(String name, Path next) {
            this.next = next;
            this.name = name;
        }

        /**
         * Adiciona o caminho como o último da cadeia
         * @param path O caminho a ser adicionado
         */
        public void pushBack(Path path) {
            Path p = this;
            while (p.next != null) {
                p = p.next;
            }
            p.next = path;
        }

        /**
         * Remove o último caminho da cadeia
         */
        public void popBack() {
            Path p = this;
            while (p.next != null && p.next.next != null) {
                p = p.next;
            }

            if (p.next != null) {
                p.next = null;
            }
        }

        /**
         * Retorna o caminho
         * @return O caminho
         */
        public String getName() {
            return name;
        }

        /**
         * Retorna o caminho do próximo objeto
         * @return O caminho do próximo objeto
         */
        public Path getNext() {
            return next;
        }

        /**
         * Verifica se este caminho possui um próximo
         * @return Indica se há um próximo caminho
         */
        public boolean hasNext() {
            return next != null;
        }

        /**
         * Retorna uma cópia do objeto
         * @return A cópia do objeto
         */
        @Override
        public Path clone() {
            Path cl = new Path(this.name,  null);
            if (this.next != null) {
                cl.next = this.next.clone();
            }
            return cl;
        }

        /**
         * Retorna a distância de caminhos entre este e o último
         * @return O tamanho da cadeia de caminhos
         */
        public int getSize() {
            int c = 0;
            Path p = this;
            while (p != null) {
                c++;
                p = p.next;
            }
            return c;
        }
    }

    /**
     * Enumeração dos tipos de ação em um dicionário MDP
     */
    enum ActionType {
        REMOVED, INSERTED
    }
}
