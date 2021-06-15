var v0 = new String('test string');
if (v0.search('String') !== -1) {
    $ERROR('#1: var aString = new String("test string"); aString.search("String")=== -1. Actual: ' + v0.search('String'));
}
