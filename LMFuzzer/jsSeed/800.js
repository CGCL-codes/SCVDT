var v0 = new Array(2);
if (v0.length === 1) {
    $ERROR('#1: var x = new Array(2); x.length !== 1');
}
if (v0[0] === 2) {
    $ERROR('#2: var x = new Array(2); x[0] !== 2');
}
