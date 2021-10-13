package br.ufsc.labsec.signature.exceptions;


public class EmptySignatureReportListException extends Exception {

    public EmptySignatureReportListException() {
        super();
    }

    public EmptySignatureReportListException(String msg) {
        super(msg);
    }

}
