from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

class FinCryptKey(univ.Sequence):
    pass


FinCryptKey.componentType = namedtype.NamedTypes(
    namedtype.NamedType('keysize', univ.Integer()),
    namedtype.NamedType('mod', univ.Integer()),
    namedtype.NamedType('exp', univ.Integer()),
    namedtype.NamedType('sigmod', univ.Integer()),
    namedtype.NamedType('sigexp', univ.Integer()),
    namedtype.NamedType('name', char.UTF8String()),
    namedtype.NamedType('email', char.UTF8String())
)