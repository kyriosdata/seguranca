document.addEventListener("DOMContentLoaded", init, false);

/* Add on button click action */
function init() {
    document.getElementById("btnExpandHideAllDetails").onclick = function () {openAll();}
}

/**
 * Expand all detail tags in the report
 */
function openAll() {
    var elems = document.getElementsByTagName("details");
    document.getElementById("btnExpandHideAllDetails").innerHTML = "Fechar<br/>elementos";
    document.getElementById("btnExpandHideAllDetails").onclick = function () {closeAll();};

    for (var i = 0; i < elems.length; i++){
        elems[i].setAttribute("open", "true");
    }
}

/**
 * Close all detail tags except the "Relatório" ones in the report
 */
function closeAll() {
    var elems = document.getElementsByTagName("details");
    document.getElementById("btnExpandHideAllDetails").onclick = function () {openAll();};
    document.getElementById("btnExpandHideAllDetails").innerHTML = "Expandir<br/>elementos";

    for (var i = 0; i < elems.length; i++) {
        if (elems[i].className !== "signature-valid-true" && elems[i].className !== "signature-valid-false") {
            elems[i].removeAttribute("open");
        }
    }
}

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