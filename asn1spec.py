from pyasn1.type import univ, char, namedtype


class FinCryptPublicKey(univ.Sequence):
    pass


FinCryptPublicKey.componentType = namedtype.NamedTypes(
    namedtype.NamedType('kx', univ.Integer()),
    namedtype.NamedType('ky', univ.Integer()),
    namedtype.NamedType('name', char.UTF8String()),
    namedtype.NamedType('email', char.UTF8String())
)


class FinCryptPrivateKey(univ.Sequence):
    pass


FinCryptPrivateKey.componentType = namedtype.NamedTypes(
    namedtype.NamedType('k', univ.Integer()),
    namedtype.NamedType('name', char.UTF8String()),
    namedtype.NamedType('email', char.UTF8String())
)


class IntSequence(univ.SequenceOf):
    componentType = univ.Integer()


class FinCryptMessage(univ.Sequence):
    pass


FinCryptMessage.componentType = namedtype.NamedTypes(
    namedtype.NamedType('key', IntSequence()),
    namedtype.NamedType('message', univ.OctetString()),
    namedtype.NamedType('signature', IntSequence())
)
