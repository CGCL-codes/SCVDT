var v0 = new String('test string');
if (v0.search(/String/i) !== 5) {
    $ERROR('#1: var aString = new String("test string"); aString.search(/String/i)=== 5. Actual: ' + v0.search(/String/i));
}
