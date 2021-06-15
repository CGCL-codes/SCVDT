if (eval('var x = 1') !== undefined) {
    $ERROR('#1: eval("var x = 1") === undefined. Actual: ' + eval('var x = 1'));
}
