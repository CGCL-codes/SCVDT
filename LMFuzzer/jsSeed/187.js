if (eval('\'\xA0str\xA0ing\xA0\'') !== '\xA0str\xA0ing\xA0') {
    $ERROR('#1: eval("\'\\u00A0str\\u00A0ing\\u00A0\'") === "\\u00A0str\\u00A0ing\\u00A0"');
}
