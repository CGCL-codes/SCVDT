var v0 = new String('test');
var v1 = v0;
v0 += 'ing';
if (v0 == v1) {
    $ERROR('#1: var item = new String("test"); var itemRef = item; item += "ing"; item != itemRef');
}
;
