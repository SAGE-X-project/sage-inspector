"""Reproduce synthetic test-only fixtures without importing either SAGE core.
Uses Python integer group arithmetic and OpenSSL (cryptography) for cross-checks.
The fixed private scalars/nonces below are public test data, never signing keys.
"""
import copy, hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives import hashes

cases=[]
def add(id,op,inp,verdict='ACCEPT',output=None,source='sage-profile',why='Manual mutation of a valid fixture; SAGE 0.10.0 rejection rule.',rule='CRYPTO-02'):
    cases.append(dict(id=id,operation=op,rule_ids=[rule],source_ids=[source],derivation=why,input=inp,expected=dict(verdict=verdict,output=output or {})))
def sigcase(id,alg,pub,msg,sig,verdict='ACCEPT',**kw):
    add(id,'signature.verify',dict(algorithm=alg,public_key_hex=pub.hex(),message_hex=msg.hex(),signature_hex=sig.hex()),verdict,{'valid':True} if verdict=='ACCEPT' else {},**kw)
def jc(id,raw,canonical=None,source='sage-profile'):
    add(id,'jcs.canonicalize',{'document_hex':raw.encode().hex()},'REJECT' if canonical is None else 'ACCEPT',{} if canonical is None else {'canonical_hex':canonical.encode().hex()},source=source,why='Literal expected bytes independently transcribed/derived from JCS sorting, serialization and SAGE input rules.',rule='JCS-01' if canonical is None else 'JCS-03')
jc('jcs-recursive',' {"z":[{"b":2,"a":1},0],"a":true} ','{"a":true,"z":[{"a":1,"b":2},0]}')
jc('jcs-array-order','[3,1,2]','[3,1,2]')
jc('jcs-unicode-order','{"\ue000":1,"😀":2,"a":3}','{"a":3,"😀":2,"\ue000":1}')
jc('jcs-no-normalization','{"é":1,"é":2}','{"é":2,"é":1}')
jc('jcs-numbers','[333333333.33333329,1E30,4.50,2e-3,1e-27]','[333333333.3333333,1e+30,4.5,0.002,1e-27]','rfc8785')
jc('jcs-exponent-boundaries','[1e-6,1e-7,1e20,1e21]','[0.000001,1e-7,100000000000000000000,1e+21]','rfc8785')
jc('jcs-positive-underflow','[1e-999]','[0]')
for id,raw in [('duplicate','{"a":1,"a":2}'),('escaped-duplicate','{"a":1,"\\u0061":2}'),('surrogate','"\\ud800"'),('negative-zero','-0'),('negative-decimal-zero','-0.0'),('negative-underflow','-1e-999'),('infinity','1e999'),('trailing','{} {}'),('bom','\ufeff{}')]:jc('jcs-'+id,raw)

# RFC8032 section7.1 test1, public bytes only.
A=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
sig=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
ed25519.Ed25519PublicKey.from_public_bytes(A).verify(sig,b'')
sigcase('ed25519-rfc8032','ed25519',A,b'',sig,source='rfc8032',why='RFC8032 section7.1 TEST1 exact public key, empty message and signature; independently verified with OpenSSL.')
L=2**252+27742317777372353535851937790883648493
for id,key,msg,s in [('message',A,b'x',sig),('truncated',A,b'',sig[:-1]),('extra-byte',A,b'',sig+b'\0'),('scalar-L',A,b'',sig[:32]+L.to_bytes(32,'little')),('scalar-malleability',A,b'',sig[:32]+(int.from_bytes(sig[32:],'little')+L).to_bytes(32,'little')),('noncanonical-A',(2**255-19).to_bytes(32,'little'),b'',sig),('noncanonical-R',A,b'',(2**255-19).to_bytes(32,'little')+sig[32:])]:sigcase('ed25519-'+id,'ed25519',key,msg,s,'REJECT')

# Independent affine Edwards arithmetic. Includes equation-valid subgroup negatives.
p=2**255-19;d=(-121665*pow(121666,-1,p))%p;I=(0,1)
def addp(P,Q):
 x,y=P;u,v=Q;t=d*x*u*y*v%p
 return ((x*v+y*u)*pow(1+t,-1,p)%p,(y*v+x*u)*pow(1-t,-1,p)%p)
def mul(k,P):
 R=I
 while k:
  if k&1:R=addp(R,P)
  P=addp(P,P);k>>=1
 return R
def enc(P):return (P[1]|((P[0]&1)<<255)).to_bytes(32,'little')
y=4*pow(5,-1,p)%p;x2=(y*y-1)*pow(d*y*y+1,-1,p)%p;x=pow(x2,(p+3)//8,p)
if x*x%p!=x2:x=x*pow(2,(p-1)//4,p)%p
if x&1:x=p-x
B=(x,y);T=(0,p-1);assert mul(L,B)==I and mul(2,T)==I and T!=I
for label,P,R,r,a,parity in [('identity-A',I,B,1,0,None),('identity-R',B,I,0,1,None),('mixed-A',addp(B,T),B,1,1,0),('mixed-R',addp(B,T),addp(B,T),1,1,1)]:
 for n in range(256):
  msg=bytes([n]);k=int.from_bytes(hashlib.sha512(enc(R)+enc(P)+msg).digest(),'little')%L
  if parity is None or k%2==parity:break
 S=(r+k*a)%L
 assert mul(S,B)==addp(R,mul(k,P)),label
 assert P==I or R==I or mul(L,P)!=I or mul(L,R)!=I
 sigcase('ed25519-'+label,'ed25519',enc(P),msg,enc(R)+S.to_bytes(32,'little'),'REJECT',why='Independent affine Edwards construction: uncofactored signature equation holds, but A or R is identity or has order-2 torsion. SAGE prime-subgroup rule requires rejection.')

# ECDSA public scalar d=1 and nonce k=1: Q=G, r=G.x mod n, s=(hash+r) mod n.
# Independent OpenSSL verification checks the resulting arithmetic.
params=[('p256','ecdsa-p256-sha256',ec.SECP256R1(),int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16),hashlib.sha256(b'').digest()),('secp256k1','sage-secp256k1-keccak256',ec.SECP256K1(),int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16),bytes.fromhex('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'))]
for label,alg,curve,n,digest in params:
 key=ec.derive_private_key(1,curve).public_key();pt=key.public_numbers();pub=b'\x04'+pt.x.to_bytes(32,'big')+pt.y.to_bytes(32,'big')
 r=pt.x%n;s=(int.from_bytes(digest,'big')+r)%n;v=pt.y&1
 if s>n//2:s=n-s;v^=1
 raw=r.to_bytes(32,'big')+s.to_bytes(32,'big');suffix=bytes([v]) if label=='secp256k1' else b''
 key.verify(utils.encode_dss_signature(r,s),digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
 sigcase(label+'-valid',alg,pub,b'',raw+suffix,source='ecdsa-arithmetic',why='Test-only d=k=1 arithmetic with low-S and recovery parity adjustment; independently checked by OpenSSL over fixed digest. Keccak empty digest from keccak-hash source constant.')
 variants=[('high-s',pub,r.to_bytes(32,'big')+(n-s).to_bytes(32,'big')+(bytes([v^1]) if suffix else b'')),('zero-r',pub,bytes(32)+raw[32:]+suffix),('zero-s',pub,raw[:32]+bytes(32)+suffix),('der',pub,utils.encode_dss_signature(r,s)),('compressed-key',bytes([2+(pt.y&1)])+pt.x.to_bytes(32,'big'),raw+suffix),('off-curve',b'\x04'+bytes(64),raw+suffix),('truncated',pub,(raw+suffix)[:-1])]
 if suffix:variants += [('wrong-recovery',pub,raw+bytes([v^1])),('recovery-2',pub,raw+b'\x02'),('recovery-27',pub,raw+b'\x1b')]
 for id,pk,sg in variants:sigcase(label+'-'+id,alg,pk,b'',sg,'REJECT')
sources=[dict(id='sage-profile',kind='spec-derived',uri='sage-spec/spec/01-crypto.md',reference='Pinned SAGE 0.10.0 CRYPTO-02 and spec/02-jcs.md JCS-01/03; manual literal negatives and independent integer arithmetic.'),dict(id='rfc8032',kind='published',uri='https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1',reference='Section7.1 TEST1 public vector; no seed required.'),dict(id='rfc8785',kind='published',uri='https://www.rfc-editor.org/rfc/rfc8785.html',reference='Section3.2 and Appendix B numeric serialization values.'),dict(id='ecdsa-arithmetic',kind='spec-derived',uri='https://docs.rs/keccak-hash/latest/src/keccak_hash/lib.rs.html',reference='Keccak empty digest constant; public curve base points and ECDSA equation with test d=k=1. OpenSSL cross-check verifies fixed SHA-256/Keccak digests without SAGE imports.')]
suite=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',id='sage-jcs-signatures-0.10.0',sources=sources,cases=cases)
out=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/'vectors/0.10.0/jcs-signatures.json'
out.write_text(json.dumps(suite,indent=2,ensure_ascii=False)+'\n');print(f'{len(cases)} independently derived cases -> {out}')
