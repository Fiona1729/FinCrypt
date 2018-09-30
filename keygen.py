import random,sys,os,argparse
aj,ad,aU,at,ay,aY,aH,aw,aT,ah,ak,az,al,aC,ax=range,pow,False,True,None,len,str,open,int,vars,argparse.ArgumentParser,os.path,sys.exit,sys.stdout,random.randrange
def aA(aO):
 s=aO-1
 t=0
 while s%2==0:
  s=s//2
  t+=1
 for aE in aj(5):
  a=ax(2,aO-1)
  v=ad(a,s,aO)
  if v!=1:
   i=0
   while v!=(aO-1):
    if i==t-1:
     return aU
    else:
     i=i+1
     v=(v**2)%aO
 return at
def aF(a,b):
 while a!=0:
  a,b=b%a,a
 return b
def aS(a,m):
 if aF(a,m)!=1:
  return ay
 u1,u2,u3=1,0,a
 v1,v2,v3=0,1,m
 while v3!=0:
  q=u3//v3
  v1,v2,v3,u1,u2,u3=(u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
 return u1%m
def aG(aO):
 if(aO<2):
  return aU
 ar=[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]
 if aO in ar:
  return at
 for ap in ar:
  if(aO%ap==0):
   return aU
 return aA(aO)
def ab(ks=1024):
 while at:
  aO=ax(2**(ks-1),2**(ks))
  if aG(aO):
   return aO
def aJ(ks):
 p=ab(ks)
 q=ab(ks)
 n=p*q
 while at:
  e=ax(2**(ks-1),2**(ks))
  if aF(e,(p-1)*(q-1))==1:
   break
 d=aS(e,(p-1)*(q-1))
 aQ=(n,e)
 ao=(n,d)
 return(aQ,ao)
def an(pbm,pvm,ks):
 aQ,ao=aJ(ks)
 aC.write('N Digits: %s, D Digits: %s\n'%(aY(aH(aQ[0])),aY(aH(aQ[1]))))
 aC.write('Pub file: %s\n'%(pbm))
 fo=aw(pbm,'w')
 fo.write('%s,%s,%s'%(ks,aQ[0],aQ[1]))
 fo.close()
 aC.write('N Digits: %s, D Digits: %s\n'%(aY(aH(aQ[0])),aY(aH(aQ[1]))))
 aC.write('Priv file: %s\n'%(pvm))
 fo=aw(pvm,'w')
 fo.write('%s,%s,%s'%(ks,ao[0],ao[1]))
 fo.close()

# End of obfuscated KeyGen code
# Rest is argument parsing
parser = argparse.ArgumentParser(description='Generate key files for the SECRET cipher')
parser.add_argument('--keysize', '-K', type=int, required=False, default=2048, help='Keysize in bits.')
parser.add_argument('public_key_file', nargs='?', default=None, help='File to write public key to.')
parser.add_argument('private_key_file', nargs='?', default=None, help='File to write private key to.')
args = vars(parser.parse_args())

if os.path.exists(args['private_key_file']) or os.path.exists(args['public_key_file']) or args['private_key_file'] is None or args['public_key_file'] is None:
    sys.exit('Key files already exist!')


an(args['private_key_file'], args['public_key_file'], args['keysize'])
