document.addEventListener("DOMContentLoaded", init, false);

/* Add listener and onChange function for signature file uploads */
function init() {
    document.querySelector('#signature_file0').addEventListener('change', handleFileSelect, false);
    setDetachedSelectionChange(document.getElementById('detached_file_selection0'), 0);
}

/* Handle a selected (uploaded) signature file. Triggered on file upload, working as a listener of #signature_file0 */
function handleFileSelect(e) {
    if (!e.target.files) {
        return;
    }

    var files = e.target.files;
    // if (files.length > 1) {
    //     document.getElementById('pdf_lbl').hidden = true;
    //     document.getElementById('html_value').checked = true;
    //     document.getElementsByName('report_type')[0].value = "HTML";
    // }

    document.getElementById('sig_lbl0').hidden = true;  // hide "SELECIONA ASSINATURA" label
    document.getElementById('sig_span0').hidden = false;  // show "ARQUIVO DE ASSINATURA 1"
    for (var i = 0; i < files.length; i++) {
        createSignatureElements(i);

        // shows html objects just created (corresponding to the file 'i') and properly assign the file itself
        document.getElementById('signature_div' + i).hidden = false;
        document.getElementById('signature_text_box' + i).value = files[i].name;
        document.getElementById('divider' + i).hidden = false;
    }

    if (files.length < 1) {
        $(document).ready(function () {
            $("#no_signatures").modal('show');
        });
        setVerifyBtnDisabled(true);
        return;
    }

    prepareElementsToVerification();
}

/** Do POST to Conformance Verifier base to identify detached/valid ICP-Brasil signatures and set onClick() for
 * "verify button".
 *
 * Some HTML elements variables change, for example: signature file fields are frozen,
 * accepting changes just further, on detached filds.
 */
function prepareElementsToVerification() {
    document.getElementById('verify').submit();
    document.getElementById('verify').target = '';
    document.getElementById('verify').action = 'webreport';
    document.getElementById('btn_verify').onclick = function () {
        var img = document.createElement('img');
        img.setAttribute('id', 'loading');
        img.setAttribute('src', 'loading.gif');
        this.replaceWith(img);
        document.getElementById('signature_file0').disabled = false;
        setTimeout(function () {
            document.getElementById('verify').submit();
        }, 100);
        if (document.getElementById("pdf_value").checked) {
            checkForCookies()
        }
    };
}

function checkForCookies() {
    cookieChecking = window.setInterval(function () {
        if (getCookie("downloadChecker") == 'sent') {
            loading.remove()
            clearInterval(cookieChecking)
            document.getElementById('avalie').hidden = false
        }
    }, 100);
}

/** Create necessary elements (divs, labels and dividers) for a signature file 'i'. The corresponding elements are also
 * already created for a detached signature.
 *
 * Depending on if signature 'i' is a detached signature or not, the "detached elements" are further shown.
 *
 * @param i Used for indexing signature file elements (i > 0).
 *      If signature 'i' is detached, also create the corresponding elements (divs and labels for detached file).
 */
function createSignatureElements(i) {
    if (!i) {
        return;
    }

    var sigDiv = createSignatureDiv(i);
    var detachedDiv = createDetachedDiv(i);

    var divider = document.createElement('hr');
    divider.hidden = true;
    divider.setAttribute('id', 'divider' + i);

    var form = document.getElementById('verify');
    var verifyBtn = document.getElementById('btn_verify');
    form.insertBefore(sigDiv, verifyBtn);
    form.insertBefore(detachedDiv, verifyBtn);
    form.insertBefore(divider, verifyBtn);
}

/** Create div for signature file 'i' and the elements it contains (e.g. text box).
 *
 * @param i Signature file index, used for created elements identification.
 * @returns {Node} the created div.
 */
function createSignatureDiv(i) {
    var sig_div = document.getElementById('signature_div0');
    var newSigDiv = sig_div.cloneNode(false);
    newSigDiv.setAttribute('id', 'signature_div' + i);

    var signature_text_box = document.getElementById('signature_text_box0');
    var newSigTxtBox = signature_text_box.cloneNode(true);
    newSigTxtBox.setAttribute('name', 'signature_text_box' + i);
    newSigTxtBox.setAttribute('id', 'signature_text_box' + i);

    var signature_text_box = document.getElementById('signature_text_box0');
    var newSigTxtBox = signature_text_box.cloneNode(true);
    newSigTxtBox.setAttribute('name', 'signature_text_box' + i);
    newSigTxtBox.setAttribute('id', 'signature_text_box' + i);

    var sig_span = document.getElementById('sig_span0');
    var newSigSpan = sig_span.cloneNode(false);
    newSigSpan.setAttribute('name', 'sig_span');
    newSigSpan.setAttribute('id', 'sig_span' + i);
    var spanText = document.createTextNode('ARQUIVO DE ASSINATURA ' + (i + 1));
    newSigSpan.appendChild(spanText);

    var sig_lbl = document.getElementById('sig_lbl0');
    var newSigLbl = sig_lbl.cloneNode(false);
    newSigLbl.setAttribute('name', 'sig_lbl');
    newSigLbl.setAttribute('id', 'sig_lbl' + i);
    newSigLbl.setAttribute('class', 'select selectlbl');

    newSigDiv.appendChild(newSigTxtBox);
    newSigDiv.appendChild(newSigSpan);
    newSigDiv.appendChild(newSigLbl);

    return newSigDiv;
}

/** Create div for detached file 'i' and the elements it contains (e.g. text box).
 *
 * @param i Detached file index, used for created elements identification.
 * @returns {Node} the created div.
 */
function createDetachedDiv(i) {
    var detached_div = document.getElementById('detached_div0');
    var newDetDiv = detached_div.cloneNode(false);
    newDetDiv.setAttribute('id', 'detached_div' + i);

    var detChooseHeader = document.getElementById('detchooseheader0');
    var newDetChooseHeader = detChooseHeader.cloneNode(true);
    newDetChooseHeader.setAttribute('id', 'detchooseheader' + i);

    var detached_text_box = document.getElementById('detached_text_box0');
    var newDetTextBox = detached_text_box.cloneNode(true);
    newDetTextBox.setAttribute('id', 'detached_text_box' + i);

    var det_file_selection = document.getElementById('detached_file_selection0');
    var newDetFileSelection = det_file_selection.cloneNode(true);
    newDetFileSelection.setAttribute('name', 'detached_file' + i);
    newDetFileSelection.setAttribute('id', 'detached_file_selection' + i);
    setDetachedSelectionChange(newDetFileSelection, i);

    var detached_label = document.getElementById('det_selection_label');
    var newDetLabel = detached_label.cloneNode(true);
    newDetLabel.setAttribute('id', 'det_selection_label' + i);
    newDetLabel.setAttribute('for', 'detached_file_selection' + i);

    newDetDiv.appendChild(newDetChooseHeader);
    newDetDiv.appendChild(newDetTextBox);
    newDetDiv.appendChild(newDetFileSelection);
    newDetDiv.appendChild(newDetLabel);

    return newDetDiv;
}

/** Set onChange function for text box 'x' text box.
 * On change, 'x' just has its text properly formatted.
 *
 * @param x Text box of a detached file
 * @param i Detached file index
 */
function setDetachedSelectionChange(x, i) {
    x.onchange = function () {
        document.getElementById('detached_text_box' + i).value
            = this.value.split('\\').pop().split('/').pop();
    };
}

/*
 * Avoid enabling verify button with no selected signature when accessing the page
 * through browser history.
 */
$(window).bind("pageshow", function() {
    var hidden_iframe = document.getElementsByName('hidden_iframe')[0];
    hidden_iframe.contentDocument.body.innerText = "{}";
    hidden_iframe_event();
});

/** Receive and handle a POST response, which is set on a hidden iframe (the only on in the page).
 *
 * The response is a JSON containing a simple dictionary for each signature file submitted.
 * Depending on the validity of the submitted signatures, a modal alerting the user is shown of not,
 * as the activation of "verify button".
 */
let hasSignature;
let notIcpBr;
function hidden_iframe_event() {
    notIcpBr = false;
    var hidden_iframe = document.getElementsByName('hidden_iframe')[0];
    var content = hidden_iframe.contentDocument.body.innerText || "{}";
    var obj = JSON.parse(content);
    if (obj.hasOwnProperty("limit")) {
        if (!alert("O limite de arquivos de assinatura é " + obj.limit + "!")) {
            window.location.reload(true);
        }
    }

    for (var key in obj) {
        if (obj[key]['notICPBrSig']) {
            notIcpBr = true;
            $(document).ready(function () {
                $("#not_icpbrsig_alert").modal('show');
            });
        } else if (!obj[key]['isValidSignature']) {
            hasSignature = false;
            $(document).ready(function () {
                $("#not_signature_alert").modal('show');
            });
        }
        var notDetached = !obj[key]['isDetached'];
        showDetachedFields(notDetached, key);
        // var hidden_iframe = document.getElementsByName('hidden_iframe')[0];
        hidden_iframe.contentDocument.body.innerText = "{}";
    }

    if (content !== "{}" && hasSignature == null) {
        //! POST response is not empty, "verify button" might be enabled
        hasSignature = true;
    }
    checkForEnablingVerifyButton();
}

document.getElementsByName('hidden_iframe')[0].onload = function () {
    hidden_iframe_event();
};

/** Set visibility of elements corresponding to a detached file.
 * @param show - 'true' to show the corresponding elements and 'false' otherwise
 * @param filename Refers to the attached file related to the detached which its visibility is being set.
 */
function showDetachedFields(show, filename) {
    var sigFiles = document.getElementById("signature_file0").files;  // all uploaded files (.p7s, .xml or .pdf)
    for (var i = 0; i < sigFiles.length; ++i) {
        if (sigFiles[i].name === filename) {
            document.getElementById('detached_file_selection' + i).disabled = show;
            document.getElementById('detached_text_box' + i).disabled = show;
            document.getElementById('detached_div' + i).hidden = show;
            return;
        }
    }
}

/** Change the state of button 'btn_verify' (html id)
 * modifying its style and setting its variable 'disable'.
 *
 * @param disable - 'true' if the state of the button should be 'disabled', 'false' otherwise
 */
function setVerifyBtnDisabled(disable) {
    var verifyBtn = document.getElementById('btn_verify');
    if (disable) {
        verifyBtn.classList.remove('button');
        verifyBtn.classList.add('disabled');
        verifyBtn.disabled = true;
    } else {
        verifyBtn.classList.remove('disabled');
        verifyBtn.classList.add('button');
        verifyBtn.disabled = false;
    }
}

/* Set onClick functions for each close button of modals which alerts the user. */
$(document).ready(function () {
    var url = window.location.href;
    if (!url.endsWith("/inicio")) {
        url = url + "inicio";
    }
    document.getElementById('close_alert0').onclick = function () {
        window.location.replace(url);
    };
    document.getElementById('close_alert1').onclick = function () {
        window.location.replace(url);
    };
    document.getElementById('close_alert2').onclick = function () {
        window.location.replace(url);
    };
});

document.getElementById('html_value').onchange = function () {
    document.getElementsByName('report_type')[0].value = this.value;
};

document.getElementById('pdf_value').onchange = function () {
    document.getElementsByName('report_type')[0].value = this.value;
};

function getCookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i <ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) === ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) === 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

function alertUserOfTermsOfUse(alert) {
    var p = $('#chk_box_alert');
    if (alert) {
        p.text("* Precisa-se aceitar os termos de uso para verificar uma assinatura");
    } else {
        p.text("");
    }
}

function checkForEnablingVerifyButton() {
    var check_bnt = document.getElementById("termos-modal-check");
    if (hasSignature && !notIcpBr && check_bnt.checked) {
        setVerifyBtnDisabled(false);
    } else {
        setVerifyBtnDisabled(true);
    }
    if (check_bnt.checked) {
        alertUserOfTermsOfUse(false);
    } else {
        alertUserOfTermsOfUse(true);
    }
}

// Open terms of use on load
function popOnLoadTermsOfUse() {
    var termsOfUse = getCookie("termsofuse");
    if (termsOfUse !== 'accepted') {
        $('#termosModal').modal('show');
    } else {
        document.getElementById("termos-modal-check").checked = true;
    }
}

document.addEventListener('DOMContentLoaded', function () {
    popOnLoadTermsOfUse();
});

function createExpireDate() {
    var date = new Date();
    var SEC = 1000;
    var MIN = 60*SEC;
    date.setTime(date.getTime() + 30*MIN);
    return date;
}

document.getElementById("termos-modal-check").addEventListener("change", function () {
    var date = createExpireDate();
    if (this.checked) {
        document.cookie = "termsofuse=accepted;expires=" + date.toUTCString() + ";path=/";
    } else {
        document.cookie = "termsofuse=;expires=" + date.toUTCString() + ";path=/";
    }
    checkForEnablingVerifyButton();
});

function avalie() {
    try {
        requestLink({
            servico: 'verificar_conformidade',
            etapa: 'Única.'
        })
    } catch (e) {
        if (e instanceof ReferenceError) {
            $('#no_certificate_installed').modal('show');
        }
    }
}