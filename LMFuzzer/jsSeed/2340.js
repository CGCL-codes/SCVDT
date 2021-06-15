var v0 = false;
function f0(x, self) {
    if (x > 0)
        self(x - 1, self);
    else if (v0)
        self(NaN, self);
}
for (var v1 = 0; v1 < 40; ++v1)
    f0(1, f0);
v0 = true;
f0(1, f0);
