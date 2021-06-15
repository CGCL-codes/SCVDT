if (!('foo' in this)) {
    (1, eval)('"use strict"; var foo = 88;');
    if ('foo' in this) {
        $ERROR('Strict indirect eval leaked a top level declaration');
    }
}
