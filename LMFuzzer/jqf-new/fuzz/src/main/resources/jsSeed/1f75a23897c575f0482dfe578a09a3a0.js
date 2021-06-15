try {
    new Array(-1);
    $ERROR('#1.1: new Array(-1) throw RangeError. Actual: ' + new Array(-1));
} catch (e) {
    if (e instanceof RangeError !== true) {
        $ERROR('#1.2: new Array(-1) throw RangeError. Actual: ' + e);
    }
}
try {
    new Array(4294967296);
    $ERROR('#2.1: new Array(4294967296) throw RangeError. Actual: ' + new Array(4294967296));
} catch (e) {
    if (e instanceof RangeError !== true) {
        $ERROR('#2.2: new Array(4294967296) throw RangeError. Actual: ' + e);
    }
}
try {
    new Array(4294967297);
    $ERROR('#3.1: new Array(4294967297) throw RangeError. Actual: ' + new Array(4294967297));
} catch (e) {
    if (e instanceof RangeError !== true) {
        $ERROR('#3.2: new Array(4294967297) throw RangeError. Actual: ' + e);
    }
}