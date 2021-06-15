if (eval('for(false;false;false);') !== undefined) {
    $ERROR('#1: eval("for(false;false;false);") === undefined. Actual: ' + eval('for(false;false;false);'));
}
