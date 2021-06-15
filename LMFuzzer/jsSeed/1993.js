Array.prototype[1] = 1;
var v0 = [0];
v0.length = 2;
if (v0.toString() !== '0,1') {
    $ERROR('#1: Array.prototype[1] = 1; x = [0]; x.length = 2; x.toString() === "0,1". Actual: ' + v0.toString());
}
