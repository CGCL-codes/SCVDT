var v0 = new String('test string');
if (v0.search('notexist') !== -1) {
    $ERROR('#1: var aString = new String("test string"); aString.search("notexist")=== -1. Actual: ' + v0.search('notexist'));
}
