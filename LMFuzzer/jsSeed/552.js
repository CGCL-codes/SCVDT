for (var v0 in Math) {
    if (v0 === 'PI') {
        $ERROR('#1: Value Property PI of the Math Object hasn\'t attribute DontEnum: \'for(x in Math) {x==="PI"}\'');
    }
}
