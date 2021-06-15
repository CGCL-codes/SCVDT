try {
    Reflect.parse(Array(3000).join('x + y - ') + 'z');
} catch (e) {
}
if (typeof reportCompare === 'function')
    reportCompare(true, true);
