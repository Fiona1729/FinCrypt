import sys,argparse
d,r,I,F,S,K,v,x=range,len,min,chr,pow,str,int,sys.exit
def D(k,Z=1<<7):
 j=k.encode('\x61\x73\x63\x69\x69')
 e=[]
 for m in d(0,r(j),Z):
  Y=0
  for i in d(m,I(m+Z,r(j))):
   Y+=j[i]*((1<<8)**(i%Z))
  e.append(Y)
 return e
def p(e,q,Z=1<<7):
 k=[]
 for Y in e:
  E=[]
  for i in d(Z-1,-1,-1):
   if r(k)+i<q:
    U=Y//((1<<8)**i)
    Y=Y%((1<<8)**i)
    E.insert(0,F(U))
  k.extend(E)
 return ''.join(k)
def h(k,l,Z=1<<7):
 a=[]
 n,e=l
 for T in D(k,Z):
  a.append(S(T,e,n))
 return a
def u(a,q,l,Z=1<<7):
 w=[]
 n,d=l
 for T in a:
  w.append(S(T,d,n))
 return p(w,q,Z)
def P(l):
 y,n,N=l.split(',')
 return(v(y),v(n),v(N))
def V(l,k,Z=1<<7):
 y,n,e=P(l)
 if y<Z*8:
  x('Invalid Blocksize')
 a=h(k,(n,e),Z)
 for i in d(r(a)):
  a[i]=K(a[i])
 g=','.join(a)
 g='%s_%s_%s'%(r(k),Z,g)
 return g
def H(l,C):
 y,n,d=P(l)
 q,W,E=C.split('_')
 q=v(q)
 W=v(W)
 if y<W*8:
  x('Invalid Blocksize')
 a=[]
 for T in E.split(','):
  a.append(v(T))
 return u(a,q,(n,d),W)


# Now we're done with obfuscated encryption code.
# From here on we're setting up command-line args and
# Calling encryption and decryption functions
parser = argparse.ArgumentParser(description='Encrypt and decrypt using a SECRET cipher')
parser.add_argument('--encrypt', '-e', action='store_true', help='Use this flag to encrypt instead of decrypt')
parser.add_argument('--blocksize', '-b', nargs=1, type=int, required=False, default=1<<7, help='Don\'t mess with this')
parser.add_argument('keyfile', type=argparse.FileType('r'), default=None, help='File for key. Usually named public key for encryption and private key for decryption')
parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='Input file to read from and encrypt/decrypt. Defaults to stdin')
args = vars(parser.parse_args())

if args['keyfile'] is None:
    sys.exit('Key required for encryption and decryption!')

if args['encrypt']:
    encrypted = V(args['keyfile'].read(), '\n'.join(args['infile'].readlines()), args['blocksize'])
    sys.stdout.write(encrypted)
else:
    decrypted = H(args['keyfile'].read(), '\n'.join(args['infile'].readlines()))
    sys.stdout.write(decrypted)