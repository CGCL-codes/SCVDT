try {
    throw 'foo';
} catch (e) {
    'bar';
} finally {
    throw 'baz';
}
