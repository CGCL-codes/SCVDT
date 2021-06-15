var v0 = /undefined/.exec()[0];
if (v0 !== 'undefined') {
    $ERROR('#1: /undefined/.exec()[0] === "undefined". Actual: ' + v0);
}
