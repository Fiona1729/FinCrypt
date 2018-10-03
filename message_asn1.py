from pyasn1.type import univ, char, namedtype


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
