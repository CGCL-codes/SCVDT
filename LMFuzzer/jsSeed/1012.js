delete Boolean.prototype.toString;
var v0 = new Boolean();
if (v0.toString() !== '[object Boolean]') {
    $ERROR('#1: The [[Class]] property of the newly constructed object is set to "Boolean"');
}
