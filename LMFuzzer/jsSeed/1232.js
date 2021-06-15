if (eval('if (false) ;') !== undefined) {
    $ERROR('#1: eval("if (false) ;") === undefined. Actual: ' + eval('if (false) ;'));
}
