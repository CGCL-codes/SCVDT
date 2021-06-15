const v0 = v1 => (x => v1(v => x(x)(v)))(x => v1(v => x(x)(v)));
const v1 = fac => n => n <= 1 ? 1 : n * fac(n - 1);
print(`5! is ${ v0(v1)(5) }`);
