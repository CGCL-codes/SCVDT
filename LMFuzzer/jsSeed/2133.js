v0 = v0 = 1;
if (v0 !== 1) {
    $ERROR('#1: The expression x = x = 1 is the same x = (x = 1), not (x = x) = 1. Actual: ' + v0);
}
