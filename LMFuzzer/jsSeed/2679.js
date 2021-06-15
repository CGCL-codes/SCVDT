function f0() {
    for (var v0 in this) {
        if (v0 === 'Math') {
            $ERROR('#1: \'Math\' have attribute DontEnum');
        }
    }
}
f0();
