document.addEventListener("DOMContentLoaded", init, false);

/* Add listener and onChange function for file uploads and sigPol selection,
 * and onChange for the form container */

var policyInfo;

function init() {
    document.querySelector('#file_tbs').addEventListener('change', handleFileSelect, false);
    document.querySelector('#signer_certificate').addEventListener('change', handleFileSelect, false);
    document.querySelector('#sig_pol').addEventListener('change', handleSigPol, false);
    document.querySelector('#sig_format').addEventListener('change', updateSigFormat, false);
    document.querySelector('#sig_policy').addEventListener('change', handleSigPolicyPool, false);
    document.querySelector('#sig_policy_version').addEventListener('change', handleSignatureVersion, false);
    document.querySelector('#filecontainer').addEventListener('change', enableGenerateSignatureButton, false);
    document.querySelector('#xml_detached_select').addEventListener('change', handleXmlDetached, false);

    let frame = document.getElementById('policyInfoFrame');
    policyInfo = JSON.parse(frame.innerHTML);
    constructSigPol();
    constructXmlDetachedSelect();
}

/* After the user uploads a file, the form shows it in the text input */
function handleFileSelect(e) {
    if (!e.target.files) {
        return;
    }
    resetFileTBS(false);
    let files = e.target.files;
    if (e.target.id === 'file_tbs') {
        for (let i = 0; i < files.length; i++) {
            createTbsElements(i);
            document.getElementById('tbs_div' + i).hidden = false;
            document.getElementById('tbs_text_box' + i).value = files[i].name;
        }
    } else if (e.target.id === 'signer_certificate') {
        document.getElementById('certificate_text_box').value = files[0].name;
        document.getElementById('password').readOnly = false;
    }
}

function createSuiteSelectionOption(suite) {
    let oid = policyInfo["suites"][suite]["oid"]
    return createSelectOptionNode(suite, oid, suite);
}

function createFormatSelectOption(format) {
    switch (format) {
        case 'ATTACHED':
            return createSelectOptionNode('attached', 'ATTACHED', 'Anexada');
        case 'DETACHED':
            return createSelectOptionNode('detached', 'DETACHED', 'Destacado');
        case 'ENVELOPED':
            return createSelectOptionNode('enveloped' , 'ENVELOPED', 'Envelopando');
        case 'INTERNALLY_DETACHED':
            return createSelectOptionNode('internally_detached' , 'INTERNALLY_DETACHED', 'Internamente Destacada');
    }
}

function createSelectOptionNode(id, value, text) {
    let option = document.createElement("option");
    option.id = id;
    option.value = value;
    option.text = text;
    return option;
}

function createSimpleSelectOptionNode(text) {
    let option = document.createElement("option");
    option.text = text;
    return option;
}

function createDefaultSelectNode(text) {
    let option = document.createElement("option");
    option.text = text;
    option.value = '';
    return option;
}

function clearSelectOptions(select) {
    let i, L = select.options.length - 1;
    for (i = L; i >= 0; i--) {
        select.remove(i);
    }
}

function clearSigPolicyOid() {
    document.getElementById("sig_pol_servlet").value = '';
}

function clearSigSuites() {
    let sigSuiteSelection = document.getElementById("suite_sel");
    clearSelectOptions(sigSuiteSelection);
    sigSuiteSelection.add(createDefaultSelectNode("Selecione a suíte de assinatura..."))
}

function clearSigPolicies() {
    let sig_policy_select = document.getElementById('sig_policy');
    clearSelectOptions(sig_policy_select);
    sig_policy_select.add(createDefaultSelectNode("Selecione o tipo de política..."))
}

function clearSigFormat() {
    let formatsSelection = document.getElementById('sig_format');
    clearSelectOptions(formatsSelection);
    formatsSelection.add(createDefaultSelectNode("Selecione o formato da assinatura..."))
}

function clearSigPolicyVersion() {
    let sigPolicyVersionSelect = document.getElementById('sig_policy_version');
    clearSelectOptions(sigPolicyVersionSelect);
    sigPolicyVersionSelect.add(createDefaultSelectNode("Selecione a versão da política..."))
}

function handleSigPolicyPol(sig) {
    var sigPolicySelect = document.getElementById('sig_policy');
    clearSigPolicies();
    let declaredPolicies = policyInfo["policy-types"][sig]['policies'];
    var policies = [];
    for (let policy in declaredPolicies) {
        policies.push(policy)
    }
    addSelectOptions(sigPolicySelect, policies);
    showSignaturePolicy(true);
}

function isSigServletValid() {
    let value = document.getElementById("sig_pol_servlet").value;
    let is_oid = value.length !== 0;
    for (i=0; i < value.length && is_oid; i++) {
        if (!(value[i] >= '0' && value[i] <= '9') && !(value[i] === '.')) {
            is_oid = false;
        }
    }
    return is_oid || value === 'CMS' || value === 'PDF' || value === 'XML';
}

function isSigSuiteValid() {
    let value = document.getElementById("suite_sel").value;
    for (let suite in policyInfo["suites"]) {
        oid = policyInfo["suites"][suite]["oid"];
        if (value === oid) {
            return true;
        }
    }
    return false;
}

function isXmlUrlValid() {
    let value = document.getElementById('xml_url').value
    return value !== '';
}

function isFileTBSValid() {
    let value = document.getElementById('file_tbs').value;
    return value !== '';
}

function isSignerCertificateValid() {
    let value = document.getElementById('signer_certificate').value;
    return value !== '';
}

function isSigFormatValid() {
    let sigFormat = document.getElementById("sig_format");
    let value = sigFormat.options[sigFormat.selectedIndex].value;
    return value !== '';
}

function resetFileTBS(force= true) {
    if (force) {
        let txt = document.getElementById('tbs_text_box0');
        let input = document.getElementById('file_tbs');
        input.value = '';
        txt.value = '';
    }

    let i = 1;
    while (true) {
        let node = document.getElementById('tbs_div' + i);
        if (node === null) {
            break;
        }
        node.parentNode.removeChild(node);
        i++;
    }
}

function handleSignatureVersion() {
    updatePolicyOid();
    clearSigSuites();
    let oid = document.getElementById("sig_pol_servlet").value;
    let suiteSelect = document.getElementById("suite_sel");
    let suites = [];
    for (let suite in policyInfo["suites"]) {
        let contains = false;
        let oidsWithSuite = policyInfo["suites"][suite]["policies"];
        for (let i in oidsWithSuite) {
            let oidWithSuite = oidsWithSuite[i];
            if (oidWithSuite === oid) {
                suites.push(createSuiteSelectionOption(suite));
                break;
            }
        }
    }
    addRawSelectOptions(suiteSelect, suites);
    showSignatureSuite(true);
}

function updatePolicyOid() {
    let sig = document.getElementById("sig_pol").value;
    let policy = document.getElementById('sig_policy').value;
    let prefix = policyInfo['oid-ca-prefix'];
    let complement = policyInfo['policy-types'][sig]['policies'][policy]['oid-complement'];
    let version = document.getElementById('sig_policy_version').value.substring(1);
    document.getElementById("sig_pol_servlet").value = prefix + complement + "." + version;
}

function addDefaultSelectOption(select, text) {
    select.add(createDefaultSelectNode(text));
}

function addRawSelectOptions(select, options) {
    var i;
    for (i = 0; i < options.length; i++) {
        select.add(options[i])
    }
}

function addSelectOptions(select, texts) {
    var i;
    for (i = 0; i < texts.length; i++) {
        let text = texts[i];
        select.add(createSimpleSelectOptionNode(text))
    }
}

function handleSigPolicyPool() {
    clearSigPolicyVersion();
    clearSigPolicyOid();
    clearSigSuites();
    //Sig
    let sigPol = document.getElementById("sig_pol");
    let sig = sigPol.options[sigPol.selectedIndex].value;
    //Policy
    let sig_policy_select = document.getElementById('sig_policy');
    let policy  = sig_policy_select.value;

    var sig_policy_version_select = document.getElementById('sig_policy_version');

    let declaredVersions = policyInfo['policy-types'][sig]['policies'][policy]['versions'];
    var versions = [];
    for (let i in declaredVersions) {
        versions.push(declaredVersions[i]);
    }
    versions.sort();
    addSelectOptions(sig_policy_version_select, versions);
    sig_policy_version_select.hidden = false;
    document.getElementById('sig_policy_version_blankspace').hidden = false;
}

function constructSigPol() {
    let sigPol = document.getElementById("sig_pol");
    var sigTypes = [];
    sigTypes.push("CMS", "XML", "PDF");
    for (let sigType in policyInfo["policy-types"]) {
        sigTypes.push(sigType)
    }
    addDefaultSelectOption(sigPol, "Selecione o tipo de assinatura...");
    addSelectOptions(sigPol, sigTypes);
}

function handleSigPol() {
    let i;
    let sigPol = document.getElementById("sig_pol");
    var sig = sigPol.options[sigPol.selectedIndex].value;

    // Limpar entradas
    clearSigPolicies();
    clearSigPolicyVersion();
    resetFileTBS();
    clearSigPolicyOid();

    document.getElementById('blankspace').hidden = false;
    document.getElementById('sig_format').hidden = false;
    document.getElementById('sig_lbl0').hidden = false;
    document.getElementById('sig_span0').hidden = true;

    showSignaturePolicyVersion(false);
    showPDFOptionals(false);
    showSignatureSuite(false);
    showSignatureFormat(false);
    showSignaturePolicy(false);
    showXmlDetachedOptions(false);

    if (sig.value === '') {
        document.getElementById('blankspace').hidden = true;
        document.getElementById('sig_format').hidden = true;
        // document.getElementById('tbs_div0').hidden = true;
        document.getElementById('sig_lbl0').hidden = true;
        document.getElementById('sig_span0').hidden = false;
        return;
    }

    document.getElementById("sig_pol_servlet").value = '';
    let formatSelection = document.getElementById('sig_format');
    clearSigFormat();
    let suiteSelection = document.getElementById("suite_sel");
    clearSigSuites();

    if (sig === 'CMS') {
        let formats = [createFormatSelectOption('ATTACHED'), createFormatSelectOption('DETACHED')];
        addRawSelectOptions(formatSelection, formats);
        let suites = [
            createSuiteSelectionOption("SHA256withRSA"),
            createSuiteSelectionOption("SHA256withECDSA"),
            createSuiteSelectionOption("SHA512withRSA"),
            createSuiteSelectionOption("SHA512withECDSA"),
            createSuiteSelectionOption("Ed25519"),
            createSuiteSelectionOption("Ed448")
        ];
        addRawSelectOptions(suiteSelection, suites);
        document.getElementById('file_tbs').accept = "/*";
        document.getElementById("sig_pol_servlet").value = sig;
        showSignatureFormat(true);
        showSignatureSuite(true);
    } else if (sig === 'XML') {
        let formats = [
            createFormatSelectOption('ATTACHED'),
            createFormatSelectOption('DETACHED'),
            createFormatSelectOption('ENVELOPED'),
            createFormatSelectOption('INTERNALLY_DETACHED')
        ];
        addRawSelectOptions(formatSelection, formats);
        let suites = [
            createSuiteSelectionOption("SHA256withRSA"),
            createSuiteSelectionOption("SHA256withECDSA"),
            createSuiteSelectionOption("SHA512withRSA"),
            createSuiteSelectionOption("SHA512withECDSA")];
        addRawSelectOptions(suiteSelection, suites);
        document.getElementById('file_tbs').accept = ".xml";
        document.getElementById("sig_pol_servlet").value = sig;
        showSignatureFormat(true);
        showSignatureSuite(true);
    } else if (sig === 'PDF') {
        let formats = [createFormatSelectOption('ATTACHED')];
        addRawSelectOptions(formatSelection, formats);
        formatSelection.selectedIndex = 1;
        document.getElementById("sig_format_servlet").value = formatSelection.value;
        let suites = [
            createSuiteSelectionOption("SHA256withRSA"),
            createSuiteSelectionOption("SHA256withECDSA"),
            createSuiteSelectionOption("SHA512withRSA"),
            createSuiteSelectionOption("SHA512withECDSA"),
            createSuiteSelectionOption("Ed25519"),
            createSuiteSelectionOption("Ed448")
        ];
        addRawSelectOptions(suiteSelection, suites);
        document.getElementById('file_tbs').accept = ".pdf";
        document.getElementById("sig_pol_servlet").value = sig;
        showSignatureFormat(false);
        showSignatureSuite(true);
        showPDFOptionals(true);
    } else if (sig in policyInfo["policy-types"]) {
        /* Assinaturas avançadas */
        let policyFormats = policyInfo["policy-types"][sig]["formats"];
        let formats = [];
        for (let i in policyFormats) {
            formats.push(createFormatSelectOption(policyFormats[i]));
        }
        addRawSelectOptions(formatSelection, formats);
        document.getElementById('file_tbs').accept = policyInfo["policy-types"][sig]["mime"];
        document.getElementById("sig_pol_servlet").value = '';
        handleSigPolicyPol(sig);
        showSignatureFormat(true);
    }
}

function showSignatureFormat(show) {
    document.getElementById('sig_format').hidden = !show;
    document.getElementById('sig_format_blankspace').hidden = !show;
}

function showSignaturePolicyVersion(show) {
    document.getElementById('sig_policy_version').hidden = !show;
    document.getElementById('sig_policy_version_blankspace').hidden = !show;
}

function showSignatureSuite(show) {
    document.getElementById("suite_sel").hidden = !show;
    document.getElementById("suite_tooltip").hidden = !show;
    document.getElementById("sig_suite_blankspace").hidden = !show;
}

function showSignaturePolicy(show) {
    document.getElementById('sig_policy').hidden = !show;
    document.getElementById('sig_policy_blankspace').hidden = !show;
}

function showPDFOptionals(show) {
    document.getElementById('pdf_fields').hidden = !show;
    document.getElementById('pdf_reason').hidden = !show;
    document.getElementById('pdf_address').hidden = !show;
    document.getElementById('pdf_cep').hidden = !show;
    document.getElementById('pdf_city').hidden = !show;
    document.getElementById('pdf_state').hidden = !show;
    document.getElementById('blankspace').hidden = !show;
    document.getElementById('sig_suite_blankspace').hidden = show;
    for (i = 0; i < 5; i++) {
        document.getElementById('blankspacepdf' + i).hidden = !show;
    }
}

function updateSigFormat() {
    let sigFormat = document.getElementById("sig_format");
    document.getElementById("sig_format_servlet").value = sigFormat.value;
    handleSigFormat();
}

function handleSigFormat() {
    let sigPol = document.getElementById("sig_pol");
    let sigFormat = document.getElementById("sig_format");

    let isXMLDetached = (sigPol.options[sigPol.selectedIndex].value === 'XML' ||
                            sigPol.options[sigPol.selectedIndex].value === 'XADES') &&
                        sigFormat.options[sigFormat.selectedIndex].id === "detached";
    showXmlDetachedOptions(isXMLDetached);
}

function constructXmlDetachedSelect() {
    let xml_detached_select = document.getElementById("xml_detached_select");
    var xmlDetachedOptions = [];
    xmlDetachedOptions.push("Arquivo(s) local(is)", "URL");
    addDefaultSelectOption(xml_detached_select, "Selecione como o(s) arquivo(s) a ser(em) assinado(s) será(ão) buscado(s)...");
    addSelectOptions(xml_detached_select, xmlDetachedOptions);
}

function showXmlDetachedOptions(show) {
    let xml_detached_select = document.getElementById("xml_detached_select");
    xml_detached_select.selectedIndex = 0;
    xml_detached_select.hidden = !show;
    showFileSelect(!show);
    showXmlURL(false);
    document.getElementById("xml_detached_blankspace").hidden = true;
}

function showXmlURL(show) {
    document.getElementById("xml_detached").hidden = !show;
    document.getElementById("xml_url").required = show;
    if (!show) {
        document.getElementById("xml_url").value = "";
    }
}

function showFileSelect(show) {
    document.getElementById("fileselect").hidden = !show;
    document.getElementById("tbs_text_box0").required = show;
    document.getElementById("file_tbs").required = show;
    if (!show) {
        resetFileTBS();
    }
}

function handleXmlDetached() {
    let xmlOptionSelect = document.getElementById("xml_detached_select");
    let optionText = xmlOptionSelect.options[xmlOptionSelect.selectedIndex].text;

    let fileSelected = (optionText === 'Arquivo(s) local(is)');
    let urlSelected = (optionText === 'URL');
    showFileSelect(fileSelected);
    showXmlURL(urlSelected);
    document.getElementById("xml_detached_blankspace").hidden = !(fileSelected || urlSelected);
}

function enableGenerateSignatureButton() {
    let btn = document.getElementById('btn_verify');
    let sigPolValid = isSigServletValid();
    let sigFormatValid = isSigFormatValid();
    let fileTbsValid = isFileTBSValid();
    let xmlUrlValid = isXmlUrlValid();
    let signerCertificateValid = isSignerCertificateValid();
    let suiteValid = isSigSuiteValid();

    if (sigPolValid
        && sigFormatValid
        && (fileTbsValid || xmlUrlValid)
        && signerCertificateValid
        && suiteValid) {
        btn.disabled = false;
        btn.className = 'button';
    } else {
        btn.disabled = true;
        btn.className = 'disabled';
    }
}

function createTbsElements(i) {
    if (!i) {
        return;
    }

    let tbsDiv = createTbsDiv(i);

    let form = document.getElementById('form');
    let divider0 = document.getElementById('divider0');
    form.insertBefore(tbsDiv, divider0);
}

function createTbsDiv(i) {
    let tbs_div = document.getElementById('tbs_div0');
    let newTbsDiv = tbs_div.cloneNode(false);
    newTbsDiv.setAttribute('id', 'tbs_div' + i);

    let tbs_text_box = document.getElementById('tbs_text_box0');
    let newTbsTxtBox = tbs_text_box.cloneNode(true);
    newTbsTxtBox.setAttribute('name', 'tbs_text_box' + i);
    newTbsTxtBox.setAttribute('id', 'tbs_text_box' + i);

    newTbsDiv.appendChild(newTbsTxtBox);

    return newTbsDiv;
}

function togglePassword() {
    let type = document.getElementById('password').type;

    if (type === "password") {
        document.getElementById('password').type = "text";
        document.getElementById('eye').src = './visibility_off-24px.png'
    } else {
        document.getElementById('password').type = "password";
        document.getElementById('eye').src = './visibility-24px.png'
    }
}

document.getElementsByName('hidden_iframe')[0].onload = function () {
    hidden_iframe_event();
};

$(window).bind("pageshow", function() {
    var hidden_iframe = document.getElementsByName('hidden_iframe')[0];
    hidden_iframe.contentDocument.body.innerText = "{}";
    hidden_iframe_event();
});

function hidden_iframe_event() {
    var hidden_iframe = document.getElementsByName('hidden_iframe')[0];
    var content = hidden_iframe.contentDocument.body.innerText || "{}";
    var obj;
    try {
        obj = JSON.parse(content);
    } catch (exception) {
        return;
    }

    if (obj["passwordError"]) {
        $('#incorrectPassword').modal();
    } else if (obj["certPathError"]) {
        $('#certPathError').modal();
    } else if (obj["malformedFile"]) {
        $('#malformedFileError').modal();
    } else if (obj["signatureError"]) {
        $('#signatureError').modal();
    } else if (obj["algorithmError"]) {
        $('#algorithmError').modal();
    }
    hidden_iframe.contentDocument.body.innerText = "{}";
}