var v0 = 0;
if (!((v0 = 1) === v0)) {
    $ERROR('#1: var x = 0; (x = 1) === x');
}
var v0 = 0;
if (v0 === (v0 = 1)) {
    $ERROR('#2: var x = 0; x !== (x = 1)');
}
