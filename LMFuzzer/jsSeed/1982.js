if (eval('while(false);') !== undefined) {
    $ERROR('#1: eval("while(false);") === undefined. Actual: ' + eval('while(false);'));
}
