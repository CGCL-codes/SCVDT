var v0 = '(function(){ function eval(){} function eval(){} ';
for (var v1 = 0; v1 < 2048; ++v1) {
    v0 += ' try{}catch(e){}';
}
v0 += ' })()';
eval(v0);
