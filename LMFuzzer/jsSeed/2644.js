var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; //\xA0single\xA0line\xA0comment\xA0x = 1; x === 0. Actual: ' + v0);
}
