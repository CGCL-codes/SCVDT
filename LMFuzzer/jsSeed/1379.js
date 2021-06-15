function f0(x) {
    try {
        eval(x);
    } catch (e) {
    }
}
;
f0('enableGeckoProfilingWithSlowAssertions();');
f0('enableTrackAllocations(); throw Error();');
