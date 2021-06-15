for (__prop in this) {
    if (__prop === '__declared__var')
        v0 = true;
}
if (!v0) {
    $ERROR('#1: When using property attributes, {DontEnum} not used');
}
var v1;
