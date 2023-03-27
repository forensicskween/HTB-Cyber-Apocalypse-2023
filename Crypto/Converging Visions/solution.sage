from pwn import *
from Crypto.Util.number import inverse
from sage.all_cmdline import *
import sys


class attackRelic:
    def __init__(self,P,EP,a,b,p):
        self.P = P
        self.EP = EP
        self.p = p
        self.q=6089788258325039501929073418355467714844813056959443481824909430411674443639248386564763122373451773381582660411059922334086996696436657009055324008041039
        self.inc=423298202838516040093965914645844180330692880951980532523877
        self.mod=self.p*self.q
        self.a = a
        self.b = b

    def _lift(self,E, P, gf):
        x, y = map(ZZ, P.xy())
        for point_ in E.lift_x(x, all=True):
            _, y_ = map(gf, point_.xy())
            if y == y_:
                return point_

    def seedmult(self,seed):
        return (self.a * pow(seed, 3) + self.b * seed +self.inc) % self.mod

    def attack(self,P,EP):
        #https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/smart_attack.py
        E = P.curve()
        gf = E.base_ring()
        p = gf.order()
        assert E.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."
        E = EllipticCurve(Qp(p), [int(a) + p * ZZ.random_element(1, p) for a in E.a_invariants()])
        P = p * self._lift(E, P, gf)
        EP = p * self._lift(E, EP, gf)
        Gx, Gy = P.xy()
        Px, Py = EP.xy()
        return int(gf((Px / Py) / (Gx / Gy)))

    def do_all(self):
        enc_seed = self.attack(self.P,self.EP)
        assert self.EP == self.P*enc_seed
        invdx=inverse(enc_seed,self.mod)
        assert self.P==self.EP*invdx
        R = PolynomialRing(Zmod(self.p),'x')
        R.gen()
        fx=R((self.a * pow(x, 3) + self.b * x +self.inc)**2) - enc_seed
        rvals = fx.roots()
        testroots=[i[0] for i in rvals]
        recovered_vs = []
        for i in testroots:
            xv=int(i)
            fxio=self.seedmult(xv)
            Recovered=(self.P*fxio)
            recovered_vs.append(Recovered)
        potential_points = list(set(recovered_vs))
        potential_seeds = []
        for recovered_point in potential_points:
            seed_og=self.attack(self.P, recovered_point)
            if self.P*seed_og == recovered_point:
                potential_seeds.append((seed_og,recovered_point))
        if len(potential_seeds) != 0:
            needed_points = [i[1]*self.seedmult(i[0]) for i in potential_seeds]
            return needed_points
        else:
            return False


class pwnRelic:
    def __init__(self, host,port):
        self.E = None
        self.P = None
        self.EP = None
        self.p = 0
        self.a = None
        self.b = None
        self.needed = None
        self.conn = remote(host,port)

    def recover_modulus(self):
        #https://cinsects.de/tag/elliptic-curves.html
        def is_leq(m):
            res = self.send_stuff(m,1)
            return res == 'Coordinate greater than curve modulus'
        l, u = 0, 2**256
        m = 2**255
        while l + 1 != u:
            if is_leq(m): u = m
            else: l = m
            m = (u + l) // 2
        for i in range(m-2,m+2):
            res = self.send_stuff(i, 1)
            if 'Coordinate greater than curve modulus' in res:
                self.p = m+1

    def send_stuff(self,stuff,idx):
        if idx == 1:
            self.conn.sendlineafter(b'> ',b'1')
            self.conn.sendlineafter(b'x: ', str(stuff).encode())
            res = self.conn.recvline().decode().strip()
        if idx == 2:
            self.conn.sendlineafter(b'> ',b'2')
            self.conn.recvline().decode().strip()
            res = self.conn.recvline().decode().strip()
        if idx == 3:
            self.conn.sendlineafter(b'> ',b'3')
            self.conn.sendlineafter(b'x: ', str(stuff[0]).encode())
            self.conn.sendlineafter(b'y: ', str(stuff[1]).encode())
            res = self.conn.recvline().decode().strip()
        return res


    def get_points(self):
        for i in range(1,100):
            res = self.send_stuff(i, 1)
            if 'Point confirmed on curve' in res:
                res = eval(res)
                Pv = (res[1],res[2])
                break
        Qv = eval(self.send_stuff('',2))[1:]
        x1,y1,x2,y2=Pv[0],Pv[1],Qv[0],Qv[1]
        self.a,self.b = self.parameter_recovery(x1,y1,x2,y2)
        self.E = EllipticCurve(GF(self.p), [0, 0, 0, self.a, self.b])
        if self.E.lift_x(ZZ(Pv[0]))[1] == ZZ(Pv[1]) and self.E.lift_x(ZZ(Qv[0]))[1] == ZZ(Qv[1]):
           self.P = self.E(Pv)
           self.EP = self.E(Qv)
        else:
            self.conn.close()
            self.conn=remote(host,port)
            return False

    def parameter_recovery(self,x1, y1, x2, y2):
        p = self.p
    #https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/parameter_recovery.py
        a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
        b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
        return int(a), int(b)

    def gen_points(self):
        while not self.get_points():
            self.get_points()
            if self.P is not None:
                break
            
    def attack_it(self):
        self.gen_points()
        attack_relic = attackRelic(self.P,self.EP,self.a,self.b,self.p)
        if attack_relic.do_all():
            x = attack_relic.do_all()
            for y in range(len(x)):
                res = self.send_stuff( (x[y][0],x[y][1]), 3)
                if 'You have confirmed the location.' in res:
                    print(res)
                    self.conn.close()
                    break
        else:
            return False



#host,port='161.35.168.118',int(31896)
host = sys.argv[1]
port = sys.argv[2]
pwn_relic = pwnRelic(host,int(port))
pwn_relic.recover_modulus()
pwn_relic.attack_it()

