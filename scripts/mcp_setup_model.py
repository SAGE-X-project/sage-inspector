"""Finite admission model, with abstract authenticated inputs; not a core adapter."""
from dataclasses import dataclass, replace
from collections import deque

@dataclass(frozen=True)
class State:
    role: str
    phase: str
    target: str = ''
    queued: str = ''
    now: int = 0
    proofs: int = 0
    ids: int = 0
    replay: int = 0
    admitted: bool = False

def initial(role):
    if role not in ('client','server'):raise ValueError('role')
    return State(role,'CHANNEL_AUTHENTICATED' if role=='client' else 'EXPECT_INITIALIZE')

def closed(s):return replace(s,phase='CLOSED',target='',queued='')

RECEIVES=('initialize','initialize_result','initialized','ack','list','listing','bad_inner')
EVENTS=tuple(RECEIVES)+('send_initialize','send_initialized','send_list','send_ok','send_fail','drain','close','invalidate','clock_failure','rollback','tick_29999','tick_30000','tick_30001','call_0','call_1','call_2','denied_call')

def reserve(s,ident,limit):
    if s.ids & (1<<ident) or s.ids.bit_count()>=limit:return None
    return replace(s,ids=s.ids|(1<<ident))

def step(s,event,limit=3):
    if event not in EVENTS or limit not in (2,3):raise ValueError('finite model input')
    if s.phase=='CLOSED':return s
    if event in ('close','invalidate','clock_failure','rollback'):return closed(s)
    if event.startswith('tick_'):
        now=int(event[5:])
        if now<s.now:return closed(s)
        s=replace(s,now=now)
        return closed(s) if s.phase!='READY' and now>=30000 else s
    if s.phase!='READY' and s.now>=30000:return closed(s)
    if s.phase=='OUTPUT_PENDING':
        if event=='send_fail':return closed(s)
        if event=='send_ok':
            return replace(s,phase=s.target,target='',proofs=s.proofs|(4 if s.target=='READY' else 0))
        if event in RECEIVES:
            return replace(s,queued=event) if not s.queued else closed(s)
        return closed(s)
    if s.queued:
        if event!='drain':return closed(s)
        return step(replace(s,queued=''),s.queued,limit)
    if event in RECEIVES:
        bit=1<<RECEIVES.index(event)
        if s.replay & bit:return closed(s)
        s=replace(s,replay=s.replay|bit)
        # Abstract cryptographic acceptance precedes application validation.
        if event=='bad_inner':return closed(s)
    if event.startswith('call_'):
        if s.phase!='READY' or s.proofs!=7:return closed(s)
        updated=reserve(s,int(event[-1]),limit)
        return replace(updated,admitted=True) if updated else closed(s)
    if event=='denied_call':return closed(s)
    if s.role=='client':
        sends={('CHANNEL_AUTHENTICATED','send_initialize'):('WAIT_INITIALIZE',0),('INITIALIZE_ACCEPTED','send_initialized'):('WAIT_INITIALIZED_ACK',None),('NEGOTIATED','send_list'):('WAIT_DISCOVERY',1)}
        if (s.phase,event) in sends:
            target,ident=sends[s.phase,event];updated=s if ident is None else reserve(s,ident,limit)
            return replace(updated,phase='OUTPUT_PENDING',target=target) if updated else closed(s)
        receives={('WAIT_INITIALIZE','initialize_result'):('INITIALIZE_ACCEPTED',1),('WAIT_INITIALIZED_ACK','ack'):('NEGOTIATED',2),('WAIT_DISCOVERY','listing'):('READY',4)}
        if (s.phase,event) in receives:
            phase,proof=receives[s.phase,event];return replace(s,phase=phase,proofs=s.proofs|proof)
    else:
        receives={('EXPECT_INITIALIZE','initialize'):('WAIT_INITIALIZED',0,1),('WAIT_INITIALIZED','initialized'):('DISCOVERY_ONLY',None,2),('DISCOVERY_ONLY','list'):('READY',1,0)}
        if (s.phase,event) in receives:
            target,ident,proof=receives[s.phase,event];updated=s if ident is None else reserve(s,ident,limit)
            return replace(updated,phase='OUTPUT_PENDING',target=target,proofs=updated.proofs|proof) if updated else closed(s)
    return closed(s)

def invariant(before,event,after):
    if before.phase=='CLOSED' and after!=before:raise AssertionError('closed reopened')
    if before.ids & after.ids != before.ids or before.replay & after.replay != before.replay:raise AssertionError('accepted history lost')
    if after.phase=='READY' and (after.proofs!=7 or after.target):raise AssertionError('readiness without setup evidence')
    if after.phase=='READY' and before.phase!='READY':
        client_final=before.role=='client' and before.phase=='WAIT_DISCOVERY' and (event=='listing' or (event=='drain' and before.queued=='listing'))
        server_final=before.role=='server' and before.phase=='OUTPUT_PENDING' and before.target=='READY' and event=='send_ok'
        if not (client_final or server_final):raise AssertionError('readiness published outside final transition')
    if after.admitted and not before.admitted:
        if before.phase!='READY' or before.proofs!=7 or before.queued or not event.startswith('call_'):raise AssertionError('premature admission')
    if after.phase=='CLOSED' and (after.target or after.queued):raise AssertionError('closed retains pending work')
    if before.phase!='READY' and before.now>=30000 and after.phase not in ('CLOSED',):raise AssertionError('late setup publication')


def explore(role,limit=3):
    start=initial(role);queue=deque([start]);paths={start:()};edges=0;ready=admitted=False
    while queue:
        before=queue.popleft()
        for event in EVENTS:
            after=step(before,event,limit);edges+=1
            try:invariant(before,event,after)
            except AssertionError as error:raise AssertionError((str(error),paths[before]+(event,))) from error
            ready|=after.phase=='READY';admitted|=after.admitted
            if after not in paths:
                if len(paths)>=10000:raise AssertionError('exploration bound reached, incomplete search')
                paths[after]=paths[before]+(event,);queue.append(after)
    if not ready or (limit==3 and not admitted) or (limit==2 and admitted):raise AssertionError('vacuous or incorrect reachability')
    return dict(role=role,request_capacity=limit,states=len(paths),transitions=edges,ready_reachable=ready,admission_reachable=admitted)
