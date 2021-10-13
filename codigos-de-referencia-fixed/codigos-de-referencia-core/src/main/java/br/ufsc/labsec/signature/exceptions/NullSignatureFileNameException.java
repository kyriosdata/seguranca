package br.ufsc.labsec.signature.exceptions;

import br.ufsc.labsec.signature.conformanceVerifier.report.Report;

public class NullSignatureFileNameException extends Exception {

    private Report signatureReport;

    public NullSignatureFileNameException(Report r) {
        super();
        signatureReport = r;
    }

    public NullSignatureFileNameException(Report r, String msg) {
        super(msg);
        signatureReport = r;
    }

    public Report getSignatureReport() {
        return signatureReport;
    }
}
