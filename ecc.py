import math
import collections
import sha
from random import SystemRandom
random = SystemRandom()


def egcd(a, b):
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        pass
    return s0, t0, a

class FieldElement:
    """Represents an element in a finite field over a (prime) modulus."""

    def __init__(self, intvalue, modulus):
        assert (isinstance(intvalue, int))
        assert (isinstance(modulus, int))
        self._intvalue = intvalue % modulus
        self._modulus = modulus
        self._qnr = None

    @property
    def modulus(self):
        """Returns the field's modulus."""
        return self._modulus

    @staticmethod
    def _eea(a, b):
        """Extended euclidian algorithm. Returns the gcd of (a, b) and the
        Bezout-coefficients."""
        assert isinstance(a, int)
        assert isinstance(b, int)
        s, t, u, v = 1, 0, 0, 1
        while b != 0:
            q, r = (a // b, a % b)
            unew, vnew = s, t
            s = u - q * s
            t = v - q * t
            a, b = b, r
            u, v = unew, vnew
        return a, u, v

    def inverse(self):
        if int(self) == 0:
            raise Exception("Trying to invert zero")
        (gcd, u, v) = self._eea(int(self), self.modulus)
        return FieldElement(v, self.modulus)

    @property
    def is_qr(self):
        """Returns if the number is a quadratic residue according to Euler's
        criterion."""
        return not self.is_qnr

    @property
    def is_qnr(self):
        """Returns if the number is a quadratic non-residue according to
        Euler's criterion."""
        if self._qnr is None:
            self._qnr = int(self ** ((self._modulus - 1) // 2)) != 1
        return self._qnr

    @property
    def legrende_symbol(self):
        """Returns the Legrende symbol of the field element, i.e. 0 if the
        element is 0 mod p, 1 if it is a quadratic residue mod p or -1 if it is
        a quadratic non-residue mod p."""
        if self == 0:
            return 0
        elif self.is_qr:
            return 1
        else:
            return -1

    def _tonelli_shanks_sqrt(self):
        """Performs the Tonelli-Shanks algorithm to determine the square root
        on an element. Note that the algorithm only works if the value it is
        performed on is a quadratic residue mod p."""
        q = self._modulus - 1
        s = 0
        while (q % 2) == 0:
            s += 1
            q >>= 1
        assert (q * (2 ** s) == self.modulus - 1)

        while True:
            z = FieldElement(random.randint(1, self.modulus - 1), self.modulus)
            if z.is_qnr:
                break
        assert z.is_qnr
        c = z ** q

        r = self ** ((q + 1) // 2)
        t = self ** q
        m = s
        while int(t) != 1:
            i = 1

            for i in range(1, m):
                if int(t ** (1 << i)) == 1:
                    break

            b = c ** (1 << (m - i - 1))
            r = r * b
            t = t * (b ** 2)
            c = b ** 2
            m = i

        return r

    def sqr(self):
        """Return the squared value."""
        return self * self

    def sqrt(self):
        """Returns the square root of the value or None if the value is a
        quadratic non-residue mod p."""
        if self.is_qnr:
            return None

        if (self._modulus % 4) == 3:
            root = self ** ((self._modulus + 1) // 4)
            assert (root * root == self)
        else:
            root = self._tonelli_shanks_sqrt()

        if (int(root) & 1) == 0:
            return root, -root
        else:
            return -root, root

    def quartic_root(self):
        """Returns the quartic root of the value or None if no such value
        explicitly exists mod p."""
        root = self.sqrt()
        if root is not None:
            r1 = root[0].sqrt() or list()
            r2 = root[1].sqrt() or list()
            for candidate in list(r1) + list(r2):
                if (candidate ** 4) == self:
                    return candidate

    def __checktype(self, value):
        if isinstance(value, int):
            return value
        elif isinstance(value, FieldElement):
            if value.modulus == self.modulus:
                return int(value)
            else:
                raise Exception(
                    "Cannot perform meaningful arithmetic operations on field elements in different fields.")

    def sigint(self):
        """Returns a signed integer if the negative value is less than 10
        decimal digits and the absolute negated value is smaller than the
        absolute positive value."""
        neg = abs(int(-self))
        if (neg < int(self)) and (neg < 1000000000):
            return -neg
        else:
            return int(self)

    @classmethod
    def any_qnr(cls, modulus):
        """Returns any quadratic non-residue in F(modulus)."""
        for i in range(1000):
            candidate = cls(random.randint(2, modulus - 1), modulus)
            if candidate.is_qnr:
                return candidate
        raise Exception("Could not find a QNR in F_%d with a reasonable amount of tries." % modulus)

    def __int__(self):
        return self._intvalue

    def __add__(self, value):
        value = self.__checktype(value)
        if value is None:
            return NotImplemented
        return FieldElement(int(self) + value, self.modulus)

    def __sub__(self, value):
        value = self.__checktype(value)
        if value is None:
            return NotImplemented
        return FieldElement(int(self) - value, self.modulus)

    def __mul__(self, value):
        value = self.__checktype(value)
        if value is None:
            return NotImplemented
        return FieldElement(int(self) * value, self.modulus)

    def __floordiv__(self, value):
        value = self.__checktype(value)
        if value is None:
            return NotImplemented
        return self * FieldElement(value, self.modulus).inverse()

    def __pow__(self, exponent):
        assert (isinstance(exponent, int))
        return FieldElement(pow(int(self), exponent, self.modulus), self.modulus)

    def __neg__(self):
        return FieldElement(-int(self), self.modulus)

    def __radd__(self, value):
        return self + value

    def __rsub__(self, value):
        return -self + value

    def __rmul__(self, value):
        return self * value

    def __rfloordiv__(self, value):
        return self.inverse() * value

    def __eq__(self, value):
        value = self.__checktype(value)
        return int(self) == (value % self.modulus)

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, value):
        value = self.__checktype(value)
        return int(self) < value

    def __hash__(self):
        return hash((self._intvalue, self._modulus))

    def __repr__(self):
        return str(self)

    def __str__(self):

        return "{0x%x}" % (int(self))


class AffineCurvePoint:
    """Represents a point on a curve in affine (x, y) representation."""

    def __init__(self, x, y, curve):
        """Generate a curve point (x, y) on the curve 'curve'. x and y have to
        be integers. If the neutral element of the group O (for some curves,
        this is a point at infinity) should be created, use the static method
        'neutral', since representations of O differ on various curves (e.g. in
        short Weierstrass curves, they have no explicit notation in affine
        space while on twisted Edwards curves they do."""
        # Either x and y are None (Point at Infty) or both are defined
        assert (((x is None) and (y is None)) or ((x is not None) and (y is not None)))
        assert ((x is None) or isinstance(x, int))
        assert ((y is None) or isinstance(y, int))
        if x is None:
            # Point at infinity
            self._x = None
            self._y = None
        else:
            self._x = FieldElement(x, curve.p)
            self._y = FieldElement(y, curve.p)
        self._curve = curve

    @staticmethod
    def neutral(curve):
        """Returns the neutral element of the curve group."""
        return curve.neutral()

    @property
    def is_neutral(self):
        """Indicates if the point is the neutral element O of the curve (point
        at infinity for some curves)."""
        return self.curve.is_neutral(self)

    @property
    def x(self):
        """Affine X component of the point, field element of p."""
        return self._x

    @property
    def y(self):
        """Affine Y component of the point, field element of p."""
        return self._y

    @property
    def curve(self):
        """Curve that the point is located on."""
        return self._curve

    def __add__(self, other):
        """Returns the point addition."""
        assert (isinstance(other, AffineCurvePoint))
        return self.curve.point_addition(self, other)

    def __rmul__(self, other):
        return self * other

    def __neg__(self):
        """Returns the conjugated point."""
        return self.curve.point_conjugate(self)

    def __mul__(self, scalar):
        """Returns the scalar point multiplication. The scalar needs to be an
        integer value."""
        assert (isinstance(scalar, int))
        assert (scalar >= 0)

        result = self.curve.neutral()
        n = self
        if scalar > 0:
            for bit in range(scalar.bit_length()):
                if scalar & (1 << bit):
                    result = result + n
                n = n + n
        assert (result.on_curve())
        return result

    def __eq__(self, other):
        return (self.x, self.y) == (other.x, other.y)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.x, self.y))

    def on_curve(self):
        """Indicates if the given point is satisfying the curve equation (i.e.
        if it is a point on the curve)."""
        return self.curve.on_curve(self)

    def compress(self):
        """Returns the compressed point format (if this is possible on the
        given curve)."""
        return self.curve.compress(self)

    def __repr__(self):
        return str(self)

    def __str__(self):
        if self.is_neutral:
            return "(neutral)"
        else:
            return "(0x%x, 0x%x)" % (int(self.x), int(self.y))


class EllipticCurve:
    """Elliptic curve base class. Provides functionality which all curves have
    in common."""

    def __init__(self, p, n, h, gx, gy, **kwargs):
        assert (isinstance(p, int))  # Modulus
        assert ((n is None) or isinstance(n, int))  # Order
        assert ((h is None) or isinstance(h, int))  # Cofactor
        assert ((gx is None) or isinstance(gx, int))  # Generator Point X
        assert ((gy is None) or isinstance(gy, int))  # Generator Point Y
        assert ((gx is None) == (gy is None))  # Either both X and Y of g are set or none
        self._p = p
        self._n = n
        self._h = h
        if (gx is not None) and (gy is not None):
            self._G = AffineCurvePoint(gx, gy, self)
        else:
            self._G = None

        if "quirks" in kwargs:
            self._quirks = {quirk.identifier: quirk for quirk in kwargs["quirks"]}
        else:
            self._quirks = {}

        if kwargs.get('name') is not None:
            self._name = kwargs['name']
        else:
            self._name = None

        self.pretty_name = None

    @property
    def p(self):
        """Returns the prime modulus which constitutes the finite field in
        which the curve lies."""
        return self._p

    @property
    def n(self):
        """Returns the order of the subgroup that is created by the generator
        g."""
        return self._n

    @property
    def h(self):
        """Returns the cofactor of the generator subgroup, i.e. h = #E(F_p) /
        n. This will always be an integer according to Lagrange's Theorem."""
        return self._h

    @property
    def g(self):
        """Returns the generator point g of the curve or None if no such point
        was set. The generator point generates a subgroup over #E(F_p)."""
        return self._G

    @property
    def curve_order(self):
        """Returns the order of the curve in the underlying field, i.e.
        #E(F_p). Intuitively, this is the total number of points on the curve
        (plus maybe points at ininity, depending on the curve type) that
        satisfy the curve equation."""
        if (self.h is None) or (self.n is None):
            raise Exception("#E(F_p) is unknown for this curve")
        return self.h * self.n

    @property
    def frobenius_trace(self):
        """Returns the Frobenius trace 't' of the curve. Since
        #E(F_p) = p + 1	- t it follows that t = p + 1 - #E(F_p)."""
        return self.p + 1 - self.curve_order

    @property
    def hasgenerator(self):
        """Returns if a generator point was supplied for the curve."""
        return self.g is not None

    @property
    def hasname(self):
        """Returns if the curve is named (i.e. its name is not None)."""
        return self.name is not None

    @property
    def name(self):
        """Returns the name of the curve, if it was given one during
        construction. Purely informational."""
        return self._name

    @property
    def prettyname(self):
        """Returns the pretty name of the curve type. This might depend on the
        actual curve, since it may also vary on the actual domain parameters to
        include if the curve is a Koblitz curve or not."""
        return self.pretty_name

    @property
    def curvetype(self):
        """Returns a string that corresponds to the curve type. For example,
        this string can be 'shortweierstrass', 'twistededwards' or
        'montgomery'."""
        raise NotImplementedError

    @property
    def domainparamdict(self):
        """Returns the domain parameters of the curve as a dictionary."""
        return dict(self.domainparams)

    @property
    def security_bit_estimate(self):
        """Gives a haphazard estimate of the security of the underlying field,
        in bits. For most curves, this will be half the bitsize of n (but might
        be less, for example for Koblitz curves some bits might be
        subtracted)."""
        return self.n.bit_length() // 2

    @property
    def domainparams(self):
        raise NotImplementedError

    def enumerate_points(self):
        """Enumerates all points on the curve, including the point at infinity
        (if the curve has such a special point)."""
        raise Exception(NotImplemented)

    def neutral(self):
        """Returns the neutral element of the curve group (for some curves,
        this will be the point at infinity)."""
        return AffineCurvePoint(None, None, self)

    def is_neutral(self, p):
        """Checks if a given point P is the neutral element of the group."""
        return p.x is None

    def on_curve(self, p):
        """Checks is a given point P is on the curve."""
        raise NotImplementedError

    def value_at(self, x):
        raise NotImplementedError

    def point_addition(self, p, q):
        """Returns the sum of two points P and Q on the curve."""
        raise NotImplementedError

    def point_conjugate(self, p):
        """Returns the negated point -P to a given point P."""
        raise NotImplementedError

    def compress(self, p):
        """Returns the compressed representation of the point P on the
        curve. Not all curves may support this operation."""
        raise NotImplementedError

    def uncompress(self, compressed):
        """Returns the uncompressed representation of a point on the curve. Not
        all curves may support this operation."""
        raise NotImplementedError

    def __eq__(self, other):
        return self.domainparams == other.domainparams

    def __ne__(self, other):
        return not (self == other)


_TwistedEdwardsCurveDomainParameters = collections.namedtuple("TwistedEdwardsCurveDomainParameters", [ "curvetype", "a", "d", "p", "n", "g" ])


class TwistedEdwardsCurve(EllipticCurve):
    """Represents an elliptic curve over a finite field F_P that satisfies the
    Twisted Edwards equation a x^2 + y^2 = 1 + d x^2 y^2."""
    pretty_name = "Twisted Edwards"

    def __init__(self, a, d, p, n, h, gx, gy, **kwargs):
        """Create an elliptic Twisted Edwards curve given the equation
        coefficients a and d, the curve field's modulus p, the order of the
        curve n and the generator point g's X and Y coordinates in affine
        representation, Gx and Gy."""
        EllipticCurve.__init__(self, p, n, h, gx, gy, **kwargs)
        assert (isinstance(a, int))  # Curve coefficent A
        assert (isinstance(d, int))  # Curve coefficent D
        self._a = FieldElement(a, p)
        self._d = FieldElement(d, p)
        self._name = kwargs.get("name")

        # Check that the curve is not singular
        assert (self.d * (1 - self.d) != 0)

        if self._G is not None:
            # Check that the generator g is on the curve
            assert (self._G.on_curve())

            # Check that the generator g is of curve order
            assert (self.n * self.g).is_neutral

    @property
    def curvetype(self):
        return "twistededwards"

    @property
    def a(self):
        """Returns the coefficient a of the curve equation a x^2 + y^2 = 1 +
        d x^2 y^2."""
        return self._a

    @property
    def d(self):
        """Returns the coefficient d of the curve equation a x^2 + y^2 = 1 +
        d x^2 y^2."""
        return self._d

    @property
    def b(self):
        """Returns the length of the curve's field modulus in bits plus one."""
        return self._p.bit_length() + 1

    @property
    def is_complete(self):
        """Returns if the twisted Edwards curve is complete. This is the case
        exactly when d is a quadratic non-residue modulo p."""
        return self.d.is_qnr

    @property
    def domainparams(self):
        return _TwistedEdwardsCurveDomainParameters(curvetype=self.curvetype, a=self.a, d=self.d, p=self.p, n=self.n,
                                                    g=self.g)
    def neutral(self):
        return AffineCurvePoint(0, 1, self)

    def value_at(self, x):
        n = (-4 * (1 - self.d * x ** 2) * (x ** 2 - 1)).sqrt()
        if n is None:
            return None
        return n[0] // (2 * (1 - self.d * x ** 2))

    def is_neutral(self, p):
        return (p.x == 0) and (p.y == 1)

    def on_curve(self, p):
        return (self.a * p.x ** 2) + p.y ** 2 == 1 + self.d * p.x ** 2 * p.y ** 2

    def point_conjugate(self, p):
        return AffineCurvePoint(int(-p.x), int(p.y), self)

    def point_addition(self, p, q):
        x = (p.x * q.y + q.x * p.y) // (1 + self.d * p.x * q.x * p.y * q.y)
        y = (p.y * q.y - self.a * p.x * q.x) // (1 - self.d * p.x * q.x * p.y * q.y)
        return AffineCurvePoint(int(x), int(y), self)

    def __str__(self):
        if self.hasname:
            return "TwistedEdwardsCurve<%s>" % self.name
        else:
            return "TwistedEdwardsCurve<0x%x x^2 + y^2 = 1 + 0x%x x^2 y^2 mod 0x%x>" % (
                int(self.a), int(self.d), int(self.p))


class ECPublicKey:
    """Elliptic curve public key abstraction. An EC public key is just a point
    on the curve, which is why the constructor only takes this (public) point
    as a parameter. The public key abstraction allows this point to be used in
    various meaningful purposes (ECDSA signature verification, etc.)."""

    def __init__(self, point):
        self._point = point

    @property
    def curve(self):
        return self._point.curve

    @property
    def point(self):
        return self._point

    def __str__(self):
        return "PublicKey<%s>" % (str(self.point))


class ECPrivateKey:
    """Represents an elliptic curve private key."""

    def __init__(self, scalar, curve):
        """Initialize the private key with the given scalar on the given
        curve."""
        self._scalar = scalar
        self._curve = curve
        self._pubkey = ECPublicKey(self._scalar * self._curve.g)

    @property
    def scalar(self):
        """Returns the private scalar d of the key."""
        return self._scalar

    @property
    def curve(self):
        """Returns the group which is used for EC computations."""
        return self._curve

    @property
    def pubkey(self):
        """Returns the public key that is the counterpart to this private key."""
        return self._pubkey

    @staticmethod
    def generate(curve):
        """Generate a random private key on a given curve."""
        scalar = random.randint(1, curve.n - 1)
        return ECPrivateKey(scalar, curve)

    def __str__(self):
        return "PrivateKey<d = 0x%x>" % self.scalar


class ElGamal:
    def __init__(self, curve: EllipticCurve):
        assert curve.hasgenerator
        self.curve = curve

    def _encrypt_point(self, message: AffineCurvePoint, public_key: ECPublicKey):
        assert self.curve.on_curve(message)
        assert public_key.curve == self.curve
        assert self.curve.on_curve(public_key.point)

        r = random.randint(1, self.curve.n - self.curve.n // 2)

        return self.curve.g * r, message + (public_key.point * r)

    def _decrypt_point(self, c1: AffineCurvePoint, c2: AffineCurvePoint, private_key: ECPrivateKey):
        assert self.curve.on_curve(c1) and self.curve.on_curve(c2)
        assert private_key.curve == self.curve

        return c2 + self.curve.point_conjugate(c1 * private_key.scalar)

    def encrypt(self, message: int, public_key: ECPublicKey, blocksize=32):
        message_size = blocksize * 8
        curve_size = self.curve.curve_order.bit_length()

        k = curve_size - message_size

        m = message << k

        point = None

        for i in range(k ** 2):
            y = self.curve.value_at(m)
            if y is not None:
                point = AffineCurvePoint(m, int(y), self.curve)
                break
            m += 1
        if point is None:
            raise ValueError
        return self._encrypt_point(point, public_key)

    def decrypt(self, c1: AffineCurvePoint, c2: AffineCurvePoint, private_key: ECPrivateKey, blocksize=32):
        message_size = blocksize * 8
        curve_size = self.curve.curve_order.bit_length()

        k = curve_size - message_size

        decrypted = self._decrypt_point(c1, c2, private_key)

        return int(decrypted.x) >> k


class ECEIS:
    def __init__(self, curve: EllipticCurve):
        assert curve.hasgenerator
        self.curve = curve

    def exchange(self, public_key: ECPublicKey):
        k = random.randint(1, self.curve.n - 1)

        r = k * self.curve.g
        s = k * public_key.point

        return r, s

    @staticmethod
    def recover(self, r, private_key: ECPrivateKey):
        return private_key.scalar * r

        
class ECDSA:
    def __init__(self, curve: EllipticCurve):
        assert curve.hasgenerator
        self.curve = curve
        self.generator = self.curve.g


    def sign(self, hashval: int, private_key: ECPrivateKey):
        assert hashval.bit_length() < self.curve.n.bit_length()

        k = random.randint(1, self.curve.n - 1)

        r_mod_p = k * self.generator

        r = int(r_mod_p.x) % self.curve.n

        assert r != 0

        s = FieldElement(hashval + private_key.scalar * r, self.curve.n) // k

        return r, int(s)


    def validate(self, r: int, s: int, hashval: int, public_key: ECPublicKey):
        assert hashval.bit_length() < self.curve.n.bit_length()
        assert 0 < r < self.curve.n
        assert 0 < s < self.curve.n

        s = FieldElement(s, self.curve.n)

        w = s.inverse()

        u1 = int(hashval * w)
        u2 = int(r * w)

        pt = (u1 * self.curve.g) + (u2 * public_key.point)

        x1 = int(pt.x) % self.curve.n

        return x1 == r

# This is the E-521 curve from http://safecurves.cr.yp.to
CURVE = TwistedEdwardsCurve(a=1,
                            d=-376014,
                            p=0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                            n=0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b,
                            h=4,
                            gx=0x752cb45c48648b189df90cb2296b2878a3bfd9f42fc6c818ec8bf3c9c0c6203913f6ecc5ccc72434b1ae949d568fc99c6059d0fb13364838aa302a940a2f19ba6c,
                            gy=12)
