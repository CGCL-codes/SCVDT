var v0 = new Object();
var v1 = v0;
delete v1;
if (typeof v0 !== 'object') {
    $ERROR('#1: obj = new Object(); ref = obj; delete ref; typeof obj === "object". Actual: ' + typeof v0);
}
