from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

class FinCryptPublicKey(univ.Sequence):
    pass


FinCryptPublicKey.componentType = namedtype.NamedTypes(
    namedtype.NamedType('keysize', univ.Integer()),
    namedtype.NamedType('modulus', univ.Integer()),
    namedtype.NamedType('exponent', univ.Integer()),
    namedtype.NamedType('sigModulus', univ.Integer()),
    namedtype.NamedType('sigExponent', univ.Integer()),
    namedtype.NamedType('name', char.UTF8String()),
    namedtype.NamedType('email', char.UTF8String())
)

class FinCryptPrivateKey(univ.Sequence):
    pass


FinCryptPrivateKey.componentType = namedtype.NamedTypes(
    namedtype.NamedType('keysize', univ.Integer()),
    namedtype.NamedType('modulus', univ.Integer()),
    namedtype.NamedType('publicExponent', univ.Integer()),
    namedtype.NamedType('privateExponent', univ.Integer()),
    namedtype.NamedType('primeP', univ.Integer()),
    namedtype.NamedType('primeQ', univ.Integer()),
    namedtype.NamedType('sigModulus', univ.Integer()),
    namedtype.NamedType('sigPublicExponent', univ.Integer()),
    namedtype.NamedType('sigPrivateExponent', univ.Integer()),
    namedtype.NamedType('sigPrimeP', univ.Integer()),
    namedtype.NamedType('sigPrimeQ', univ.Integer()),
    namedtype.NamedType('name', char.UTF8String()),
    namedtype.NamedType('email', char.UTF8String())
)

class IntBlocks(univ.SequenceOf):
    componentType = univ.Integer()


class FinCryptMessage(univ.Sequence):
    pass


FinCryptMessage.componentType = namedtype.NamedTypes(
    namedtype.NamedType('key', IntBlocks()),
    namedtype.NamedType('iv', IntBlocks()),
    namedtype.NamedType('message', univ.OctetString()),
    namedtype.NamedType('signature', IntBlocks())
)
