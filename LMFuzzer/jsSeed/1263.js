delete Number.prototype.toString;
var v0 = new Number();
if (v0.toString() !== '[object Number]') {
    $ERROR('#1: The [[Class]] property of the newly constructed object is set to "Number"');
}
