function f0(actual, expected) {
    if (actual !== expected)
        throw new Error('bad value: ' + actual);
}
f0(unescape('%0'), '%0');
f0(unescape('%a'), '%a');
