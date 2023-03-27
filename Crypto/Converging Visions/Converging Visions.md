# Converging Visions

Category: Crypto

************Category************: Crypto

****************Points:**************** 1000

************************Difficulty:************************ hard

## Description

As you hold the relic in your hands, it prompts you to input a coordinate. The ancient scriptures you uncovered near the pharaoh's tomb reveal that the artifact is capable of transmitting the locations of vessels. The initial coordinate must be within proximity of the vessels, and an algorithm will then calculate their precise locations for transmission. However, you soon discover that the coordinates transmitted are not correct, and are encrypted using advanced alien techniques to prevent unauthorized access. It becomes clear that the true coordinates are hidden, serving only to authenticate those with knowledge of the artifact's secrets. Can you decipher this alien encryption and uncover the genuine coordinates to locate the vessels and destroy them?

## Walkthrough

First, I recommend sage to run this challenge appropriately (I always test out challenges before trying to solve them). 

### Code Analysis

This is another Elliptic Curve challenge. First thing to notice, the values of p, a and b are **imported**. Meaning, they will remain constant wether we close the connection or not. 

**class Relic:**

```python
class Relic:
    def __init__(self, p, a, b):
        self.E = EllipticCurve(GF(p), [a, b])
        self.P = None
        self.EP = None
        self.p = p
        self.prng = PRNG(p, a, b)
    def setupPoints(self, x):
        if x >= self.p:
            return 'Coordinate greater than curve modulus'
        try:
            self.P = self.E.lift_x(Integer(x))
            self.EP = self.P
        except:
            return 'Point not on curve'
        return ('Point confirmed on curve', self.P[0], self.P[1])
    def nextPoints(self):
        seed, enc_seed = self.prng.rotate()
        self.P *= seed
        self.EP *= enc_seed
        return ('New Points', self.EP[0], self.EP[1], self.P[0], self.P[1])
```

The prng is initialized with the PRNG class:

**********************class PRNG:**********************

```python
class PRNG:
    def __init__(self, p, mul1, mul2):
        self.mod = p * 6089788258325039501929073418355467714844813056959443481824909430411674443639248386564763122373451773381582660411059922334086996696436657009055324008041039
        self.exp = 2
        self.mul1 = mul1
        self.mul2 = mul2
        self.inc = int.from_bytes(b'Coordinates lost in space', 'big')
        self.seed = randint(2, self.mod - 1)
    def rotate(self):
        self.seed = (self.mul1 * pow(self.seed, 3) + self.mul2 * self.seed +
                     self.inc) % self.mod
        return self.seed, pow(self.seed, self.exp, self.mod)
```

Essentially, each time we ask for a new point, the seed is multiplied.

```python
inc = 423298202838516040093965914645844180330692880951980532523877
seed = (a*seed^3 + b*seed + inc) % prng.mod
enc_seed = seed^2 % prng.mod
```

which can be re-written as:

```python
x = seed
enc_seed = (ax^3 + bx + inc % prng.mod)^2%prng.mod
```

**************************Main function**************************

The menu gives us three choices:

1. Setup Point

Enter coordinate x. The coordinate is passed to the class Relic, and if the point is on the curve, then point P will be initialised. If it’s **not on the curve**, it will tell us ‘Point not on curve’,  if it’s bigger than **p**, it will return 'Coordinate greater than curve modulus’. So we have ways to **recover P** through this option. 

2. Receive new point

The function nextPoints in the class Relic returns four values, the coordinates of  point EP multiplied by the enc_seed and the coordinates of point P multiplied by the seed (both seeds are initialised by the PRNG class). 

3. Find true point

Here, we are asked to enter coordinates x, and y. The server will call the nextPoints() function, and compare our values to its output. **Important thing to keep in mind**, the points being verified are the points of P, aka the value multiplied by the normal seed, not the encrypted seed. The points we receive in option 2 are encrypted with the enc_seed. 

Our options are limited, we can only chose to place the original point P on the curve, and then ask for the point EP, which is at first  EP = point P * enc_seed, and then becomes EP = EP * enc_seed. 

The first thing we need to do, is to **recover** the parameters. 

## Exploit

### 1. Modulus  Recovery

The last line of code called before executing main, which I unfortunately missed, is to make sure that p.bit_length() == 256. I took SOOO Long to find it during the CTF, but now I found a [code](https://cinsects.de/tag/elliptic-curves.html) that basically does what I was doing manually snif snif. 

```python
host,port='161.35.168.118',int(31942)
conn = remote(host,port)

def recover_modulus(conn):
    def is_leq(m):
        conn.sendlineafter(b'> ',b'1')
        conn.sendlineafter(b'x: ', str(m).encode())
        res = conn.recvline().decode().strip()
        return res == 'Coordinate greater than curve modulus'
    l, u = 0, 2**256
    m = 2**255
    while l + 1 != u:
        if is_leq(m): u = m
        else: l = m
        m = (u + l) // 2
    return m

p = recover_modulus(conn)
```

We can quickly check if its correct by sending values in range p-2,p+2

```python
for i in range(p-2,p+2):
    conn.sendlineafter(b'> ',b'1')
    conn.sendlineafter(b'x: ', str(i).encode())
    res = conn.recvline().decode().strip()
    print(res)

```

p+1 is the 'alarm' value, aka, the value that tells us that it’s greater than the modulus, so that’s our **modulus**!

### 2. Parameter Recovery

To recover the parameters, we just need to ask for a couple of points, then it will be easy to recreate the curve. The code is from [here](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/parameter_recovery.py). 

 

```python
def get_points(conn):
    points = []
    for i in range(1,100):
        conn.sendlineafter(b'> ',b'1')
        conn.sendlineafter(b'x: ', str(i).encode())
        res = conn.recvline().decode().strip()
        if 'Point confirmed on curve' not in res:
            pass
        else:
         res = eval(res)
         points.append((res[1],res[2]))
        if len(points) == 2:
            break
    return points

def parameter_recovery(p, x1, y1, x2, y2):
    a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
    b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
    return int(a), int(b)

p = p+1
points = get_points(conn)
x1,y1,x2,y2=points[0][0],points[0][1],points[1][0],points[1][1]
a,b = parameter_recovery(p,x1,y1,x2,y2)
```

Now that we have our parameters, and the modulus, we can reconstruct the curve and some of the PRNG variables. 

### 3. Curve Reconstruction

Checking the Curve:

```python
E = EllipticCurve(GF(p), [0, 0, 0, a, b])
E.order()
#91720173941422125335466921700213991383508377854521057423162397714341988797837
```

When the order of a curve is equal to the modulus (which is the case here), then we have an anomolous curve. These curves are vulnerable to Smart’s Attack, and we can easily recover the multiplied values. 

Having identified the vulnerability, we can now move on to getting the next point - aka the encrypted point. It’s important to remember that the server calculates everything according to the point we send first. For the purpose of this, I’m going to resend point the coordinate for x=4, and get the next values. 

```python
conn.close()
conn = remote(host,port)
def get_vals(conn):
    conn.sendlineafter(b'> ',b'1')
    conn.sendlineafter(b'x: ', str(4).encode())
    res = conn.recvline().decode().strip()
    P = (eval(res)[1],eval(res)[2])
    conn.sendlineafter(b'> ',b'2')
    conn.recvline().decode().strip()
    res = conn.recvline().decode().strip()
    Q = (eval(res)[1],eval(res)[2])
    return P,Q

Pv,Qv=get_vals(conn)
assert E.lift_x(ZZ(Pv[0]))[1] == ZZ(Pv[1])
assert E.lift_x(ZZ(Qv[0]))[1] == ZZ(Qv[1])
P = E(Pv)
Q = E(Qv)
```

If the assertion fails, then we need to re-call the get_vals function. 

### 4. Smart’s Attack

Here is the code I used,  copied from [here](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/smart_attack.py)

```python
def _lift(E, P, gf):
    x, y = map(ZZ, P.xy())
    for point_ in E.lift_x(x, all=True):
        _, y_ = map(gf, point_.xy())
        if y == y_:
            return point_

def attack(G, P):
    E = G.curve()
    gf = E.base_ring()
    p = gf.order()
    assert E.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."

    E = EllipticCurve(Qp(p), [int(a) + p * ZZ.random_element(1, p) for a in E.a_invariants()])
    G = p * _lift(E, G, gf)
    P = p * _lift(E, P, gf)
    Gx, Gy = G.xy()
    Px, Py = P.xy()
    return int(gf((Px / Py) / (Gx / Gy)))

enc_seed = attack(P,Q)
```

So, at first, I tripped out, because the size of enc_seed was 255, whereas when I tried out the PRNG by myself, it was around the size of the modulus (767 bits). But thennnnnnn, I realized, that since the curve where this seed is used is on a way smaller field, it doesn’t matter whether we recover the full encrypted seed or not, as the seed will automatically be modular to p.  So this first seed we recovered, is the value of ****************************encrypted seed****************************, meaning, it’s the value of the modified seed^2 % mod. 

Finding the inverse of the **enc_seed** returned by smart attack **************************mod prng.mod,************************** and multiplying that with point Q gives us point P, which confirms the whole order/finite field thing.

```python
mod = p*6089788258325039501929073418355467714844813056959443481824909430411674443639248386564763122373451773381582660411059922334086996696436657009055324008041039
inc = int.from_bytes(b'Coordinates lost in space', 'big')
invdx = pow(enc_seed, -1,mod)
assert Q==P*enc_seed
assert P==Q*invdx
```

To **retrieve the original seed**, we can use sage, and reconstruct the prng rotate function. With sage, we can find the value of x by constructing a polynomial. For every root found, we test it against the original point, if they all have the same result, then we are safe. 

 

```python
def seedmult(seed):
    return (a * pow(seed, 3) + b * seed +inc) % mod

R = PolynomialRing(Zmod(p),'x')
fx=R((a * pow(x, 3) + b * x +inc)**2) - enc_seed
rvals = fx.roots()
testroots=[i[0] for i in rvals]

recovered_vs = []
for i in testroots:
    xv=int(i)
    fxio=seedmult(xv)
    Recovered=(P*fxio)
    recovered_vs.append(Recovered)

potential_points = list(set(recovered_vs))
assert len(potential_points) == 1

```

Now, we need to recover the value of the next seed. The points we recovered (potential_points) are point E. The point the server is asking is this point E multiplied by the next seed. We re-do the attack on the original point, and the recovered point to find this specific seed. Then, we just need to apply the seed multiplication function to get the new seed, and the next point:

```python
potential_seeds = []
for recovered_point in potential_points:
    enc_seed_2=attack(P, recovered_point)
    if P*enc_seed_2 == Recovered:
        potential_seeds.append((enc_seed_2,recovered_point))

if len(potential_seeds) == 1:
    needed_point = potential_seeds[0][1]*seedmult(potential_seeds[0][0])
```

Normally, there should be only one value in potential_seeds. We can send it to the server to get the flag:

```python
conn.sendlineafter(b'> ',b'3')
conn.sendlineafter(b'x: ', str(needed_point[0]).encode())
conn.sendlineafter(b'y: ', str(needed_point[1]).encode())
res = conn.recvline().decode().strip()
print(res)
#You have confirmed the location. It's dangerous however to go alone. Take this:  HTB{0Racl3_AS_a_f3A7Ur3_0n_W3aK_CURV3_aND_PRN9??_7H3_s3cur17Y_0F_0uR_CRyP70Sys73M_w1LL_c0LLAp53!!!}
```

************Flag:************ HTB{0Racl3_AS_a_f3A7Ur3_0n_W3aK_CURV3_aND_PRN9??_7H3_s3cur17Y_0F_0uR_CRyP70Sys73M_w1LL_c0LLAp53!!!}
