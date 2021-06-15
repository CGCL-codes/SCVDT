Object.defineProperty(this, 'x', {
    set: function () {
    }
});
Object.freeze(this);
eval('"use strict"; x = 20;');
