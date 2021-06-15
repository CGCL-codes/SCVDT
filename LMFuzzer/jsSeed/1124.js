v0 = new RegExp('([^b]*)+((..)|(\\3))+?Sc*a!(a|ab)(c|bcd)(<*)', 'i');
var v1 = 'aNULLxabcd';
v1.replace(v0, function (s) {
    return s;
});
