var v0 = new String('abba');
if (!String.prototype.isPrototypeOf(v0)) {
    $ERROR('#1: var __str__obj = new String("abba"); String.prototype.isPrototypeOf(__str__obj)===true');
}
