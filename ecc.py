import math
from random import SystemRandom

random = SystemRandom()

def gcd(a, b):
    """
    Calculates the GCD of two numbers using Euclid's algorithm.

    :param a: A
    :param b: B
    :return: GCD
    """

    while a != 0:
        a, b = b % a, a
    return b


def modinv(a, m):
    """
    Calculates the modular inverse of a and m using Euclid's extended algorithm

    :param a: A
    :param m: M
    :return: Modular inverse if it exists, None otherwise.
    """

    if gcd(a, m) != 1:
        return None  # If a and m aren't coprime, there is no mod inverse

    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def egcd(a, b):
    """
    Elliptic GCD

    :param a: A
    :param b: B
    :return: EGCD of A and B
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def primes(n):
    """

    :param n:
    :return:
    """
    primfac = []
    multiple = False
    d = 2
    while d * d <= n:
        dpow = 0
        while (n % d) == 0:
            dpow = dpow + 1
            multiple = True
            n /= d

        if multiple:
            primfac.append(d)
            primfac.append(dpow)
            multiple = False
        d += 1

    if n > 1:
        primfac.append(n)
        primfac.append(1)


class EllipticCurve(object):
    """ Elliptic curve
     Elliptic curves in short Weierstrass form :
       y^2 = x^3 + a4 x + a6

     - self.p (int) Finite prime field Fp. Moreover : p = 3 mod 4
     - self.n (int) Order of the curve. n is prime
     - self.a4 (int) a4 = Hash(r4)
     - self.a6 (int) a6 = Hash(r6)
     - self.r4 (int) (random)
     - self.r6 (int) (random)
     - self.gx (int) gx = Hash(r) such that x^3+a*x+b is a square.
     - self.gy (int)
     - self.r (int) (random)

     g = (gx, gy) is a point of the curve
     r4, r6 and r assure the curve is not particular
     For more information see : http://galg.acrypta.com/index.php/download
    """

    def __init__(self, p, n, a4, a6, r4, r6, gx, gy, r):
        self.p = p
        self.n = n
        self.a4 = a4
        self.a6 = a6
        self.r4 = r4
        self.r6 = r6
        self.gx = gx
        self.gy = gy
        self.r = r


    def test_point(self, x, y, z):
        res1 = (y * y) % self.p
        res2 = (x * x * x + self.a4 * x + self.a6) % self.p
        return res1 == res2 or z


    def __str__(self):
        return ' y^2 = x^3 + a4x + a6\n a4 = %s\n a6 = %s\n p = %s\n n = %s' % (self.a4, self.a6, self.p, self.n)


    def __repr__(self):
        return str(self)


    def __eq__(self, other):
        return (self.p, self.n, self.a4, self.a6) == (other.p, other.n, other.a4, other.a6)


    def __ne__(self, other):
        return not (self == other)


class Point(object):
    """ Point
     A Point is a point of an elliptic curve
     - curve (EllipticCurve) the curve containing this point
     - x (int)
     - y (int)
     - z (boolean) Indicates if the point is infinite
    """

    def __init__(self, curve, x, y, z=False):
        self.curve = curve
        self.x = x
        self.y = y
        self.z = z

        if not curve.test_point(x, y, z):
            raise Exception("The point %s is not on the given curve %s!" % (self, curve))


    def __str__(self):
        return "(%r, %r)" % (self.x, self.y)


    def is_ideal(self):
        return self.z


    def __repr__(self):
        return str(self)


    def __eq__(self, other):
        return (self.curve, self.x, self.y) == (other.curve, other.x, other.y)


    def __neg__(self):
        xq = self.x
        yq = (-self.y) % self.curve.p
        return Point(self.curve, xq, yq, False)


    def __add__(self, q):
        if self.curve != q.curve:
            raise Exception("Can't add points on different curves!")

        if self.is_ideal():
            return q

        if q.is_ideal():
            return self

        if q == -self:
            return Point(self.curve, 0, 1, True)

        xp = self.x
        yp = self.y
        xq = q.x
        yq = q.y

        # Careful here it is not a simple division,
        # but a modular inversion
        if xp == xq:
            l = ((3 * xp * xp + self.curve.a4) * modinv(2 * yp, self.curve.p))
        else:
            l = (yp - yq) * modinv((xp - xq) % self.curve.p, self.curve.p)

        xr = (l * l - xp - xq) % self.curve.p
        yr = (l * xp - yp - l * xr) % self.curve.p

        return Point(self.curve, xr, yr)


    def __mul__(self, n):
        if not isinstance(n, int):
            raise Exception("Can't scale a point by something which isn't an int!")

        if n == 0:
            return Point(self.curve, 0, 1, True)

        if n == 1:
            return self

        q = Point(self.curve, 0, 1, True)
        i = 1 << (int(math.log(n, 2)))
        while i > 0:
            q = q + q
            if n & i == i:
                q = q + self
            i = i >> 1
        return q


    def __rmul__(self, n):
        return self * n


    def __list__(self):
        return [self.x, self.y]


    def __ne__(self, other):
        return not self == other


    def __getitem__(self, index):
        return [self.x, self.y][index]


class ElGamal(object):
    def __init__(self, curve):
        self.curve = curve
        self.generator = Point(self.curve, self.curve.gx, self.curve.gy)


    def keygen(self):
        bits = int(math.log(self.curve.n, 2))
        private_key = random.getrandbits(bits - 1)
        public_key = private_key * self.generator
        return public_key, private_key


    def encrypt(self, public_key, m):
        bits = int(math.log(self.curve.n, 2))
        k = random.getrandbits(bits - 1)
        c1 = (k * public_key).x + int(m)
        c2 = k * self.generator
        return c1, c2

    @staticmethod
    def decrypt(private_key, c1, c2):
        return c1 - (private_key * c2).x


CURVE = EllipticCurve(p=8884933102832021670310856601112383279507496491807071433260928721853918699951,
                      n=8884933102832021670310856601112383279454437918059397120004264665392731659049,
                      a4=2481513316835306518496091950488867366805208929993787063131352719741796616329,
                      a6=4387305958586347890529260320831286139799795892409507048422786783411496715073,
                      r4=5473953786136330929505372885864126123958065998198197694258492204115618878079,
                      r6=5831273952509092555776116225688691072512584265972424782073602066621365105518,
                      gx=7638166354848741333090176068286311479365713946232310129943505521094105356372,
                      gy=762687367051975977761089912701686274060655281117983501949286086861823169994,
                      r=8094458595770206542003150089514239385761983350496862878239630488323200271273)
