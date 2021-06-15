try {
    Function.call(this, 'var #x  = 1;');
} catch (e) {
    if (!(e instanceof SyntaxError)) {
        $ERROR('#1: function body must be valid');
    }
}
