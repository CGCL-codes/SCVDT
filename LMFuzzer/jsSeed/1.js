if (!Object.prototype.isPrototypeOf(String.prototype)) {
    $ERROR('#1: Object.prototype.isPrototypeOf(String.prototype) return true. Actual: ' + Object.prototype.isPrototypeOf(String.prototype));
}
delete String.prototype.toString;
if (String.prototype.toString() != '[object ' + 'String' + ']') {
    $ERROR('#2: delete String.prototype.toString; String.prototype.toString() == "[object "+"String"+"]". Actual: String.prototype.toString() ==' + String.prototype.toString());
}
