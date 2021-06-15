if (eval('do ; while(false)') !== undefined) {
    $ERROR('#1: eval("do ; while(false)") === undefined. Actual: ' + eval('do ; while(false)'));
}
