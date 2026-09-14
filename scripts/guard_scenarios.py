"""Fixture authoring model only; never install or advertise this as a subject adapter."""
import copy,hashlib,json

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()

def scenarios(envelope,policy,manifest,artifacts,issuer_key,executor_key,result,sources,sign):
    fixtures=[]
    new_policy=copy.deepcopy(policy);new_policy['epoch']='00000000-0000-4000-8000-000000000090'
    new_digest=hashlib.sha256(b'sage-policy|0.10.0\0'+canonical(new_policy)).hexdigest()
    new_intent=copy.deepcopy(envelope['intent']);new_intent.update(policy_digest=new_digest,call_id='00000000-0000-4000-8000-000000000091',request_id='00000000-0000-4000-8000-000000000092',nonce='AQEBAQEBAQEBAQEBAQEBAQ')
    new_envelope=sign('intent',new_intent)
    def scenario(name,actions,client=False):
        ledger={};approved=envelope['intent']['policy_digest'];epochs={policy['epoch']};nonces=set();outer=set();now=0;intact=True;allowed=True;measured=True;clock=True;signer=True
        effects=dict(reservations=0,dispatch=0,responses=0,result_signatures=0,consumed=0,polls=0)
        arguments=[];instances=[];terminal=None;outstanding={'a','b','c','d'};last_poll=None;steps=[]
        results={s:result(s) for s in ('pending','completed','rejected','unknown')}
        def add(op,inp,ok=True,out=None):steps.append(dict(id='step-'+str(len(steps)),operation=op,input=copy.deepcopy(inp),timeout_ms=5000,expected=dict(verdict='ACCEPT' if ok else 'REJECT',output=copy.deepcopy(out or {}) if ok else {}),effects=copy.deepcopy(effects)))
        add('control.guard.setup',dict(envelope=envelope,policy=policy,manifest=manifest,artifacts=artifacts,issuer_public_key_hex=issuer_key,executor_public_key_hex=executor_key,now=1700000000,clock_trusted=True,ledger_intact=True,artifact_instance='artifact-A',signer_fixtures=results,outstanding_invocations=sorted(outstanding),client=client,recovery_policy=new_policy,recovery_envelope=new_envelope,recovery_signer_fixtures={s:result(s,new_envelope) for s in results}))
        def apply(a):
            nonlocal now,intact,allowed,measured,clock,signer,terminal,last_poll,approved
            kind=a['action'];ok=True;output={}
            if kind=='clock':now=a['elapsed'];return True,{}
            if kind=='retire':allowed=False
            elif kind=='measure':measured=a['same_immutable_instance']
            elif kind=='clock-trust':clock=a['trusted']
            elif kind=='signer':signer=a['available']
            elif kind=='gate-failure':allowed=False
            elif kind=='peer-provision':return False,{}
            elif kind=='lose-ledger':intact=False;ledger.clear()
            elif kind=='recover':
                # Scope recovery is not an empty-ledger restart or merely a new UUID.
                if not a.get('trusted_admin') or not a.get('scope_synchronized') or not a.get('old_commitments_retired') or not a.get('new_mapping_durable') or a['descriptor']['epoch'] in epochs:return False,{}
                epochs.add(a['descriptor']['epoch']);approved=hashlib.sha256(b'sage-policy|0.10.0\0'+canonical(a['descriptor'])).hexdigest();intact=True;allowed=True
            elif kind=='crash':
                for e in ledger.values():
                    if e['state'] in ('RESERVED','EXECUTING'):e['state']='UNKNOWN';e['terminal']=None
            elif kind=='client-new-call':
                return (False,{}) if a['reason']=='retry-unknown' else (True,{})
            elif kind=='client-poll':
                if terminal is not None or now>=300 or (last_poll is not None and now-last_poll<1):return False,{}
                last_poll=now;effects['polls']+=1
            elif kind=='client-result':
                invoke=a['invocation'];env=a['envelope'];status=env['result']['status']
                if invoke not in outstanding or not a.get('verified',True):return False,{}
                outstanding.remove(invoke)
                if status=='pending':return True,dict(disposition='ignored' if terminal else 'pending')
                if terminal is not None:return (True,dict(disposition='ignored')) if digest(env)==terminal else (False,{})
                terminal=digest(env);effects['consumed']+=1;return True,dict(disposition='consumed')
            else:
                env=a.get('envelope',envelope);i=env['intent'];cid=i['call_id'];e=ledger.get(cid);nonce=i['nonce'];ident=digest(env)
                if kind in ('submit','reject'):
                    invocation=a.get('invocation','invoke-'+str(len(steps)))
                    if invocation in outer:return False,{}
                    outer.add(invocation)
                    if not intact or not clock or not allowed or not measured or now>=300 or not a.get('verified',True) or i['policy_digest']!=approved:return False,{}
                    if e:
                        if kind=='reject' or e['digest']!=ident:return False,{}
                    else:
                        if nonce in nonces:return False,{}
                        nonces.add(nonce);effects['reservations']+=1
                        e=dict(state='REJECTED' if kind=='reject' else 'RESERVED',digest=ident,arguments=copy.deepcopy(i['arguments']),terminal=None);ledger[cid]=e
                    state=e['state'];status=state.lower() if state in ('COMPLETED','REJECTED','UNKNOWN') else 'pending'
                    if not signer:return False,{}
                    if status=='pending':effects['result_signatures']+=1
                    elif e['terminal'] is None:e['terminal']=digest(result(status,env));effects['result_signatures']+=1
                    effects['responses']+=1;return True,dict(status=status)
                if kind=='dispatch':
                    if not e or e['state']!='RESERVED':return False,{}
                    if not intact or not allowed or not measured or not clock or now>=300:
                        e['state']='REJECTED';return False,{}
                    e['state']='EXECUTING';effects['dispatch']+=1;arguments.append(e['arguments']);instances.append('artifact-A')
                elif kind=='complete':
                    if not e or e['state']!='EXECUTING' or not signer or a.get('persistence_failure',False):return False,{}
                    e['state']='COMPLETED';e['terminal']=digest(results['completed']);effects['result_signatures']+=1
                else:raise ValueError(kind)
            return ok,output
        for action in actions:
            a=copy.deepcopy(action)
            if a['action']=='race':
                verdicts=[]
                for item in a['gate_order']:
                    ok,_=apply(item);verdicts.append('ACCEPT' if ok else 'REJECT')
                add('subject.parallel',dict(action='race',barrier='before-protected-commit',gate_order=a['gate_order']),out=dict(verdicts=verdicts))
            else:
                ok,output=apply(a);add('subject.call',a,ok,output)
            add('subject.call',dict(action='inspect'),out=dict(entries={k:ledger[k] for k in sorted(ledger)},ledger_intact=intact,policy_active=allowed,measured=measured,clock_trusted=clock,approved_policy=approved,dispatch_arguments=arguments,dispatch_instances=instances,client_terminal=terminal))
        fixtures.append(dict(schema_version=2,protocol_version='0.10.0',profile='stateful-scenario',id='guard-'+name,sources=sources,steps=steps))
    A=lambda kind,**kw:dict(action=kind,**kw)
    scenario('pending-completed',[A('submit'),A('dispatch'),A('submit'),A('complete'),A('submit')])
    scenario('intact-absence-retry',[A('submit'),A('dispatch'),A('complete'),A('submit')])
    scenario('outer-replay',[A('submit',invocation='same'),A('submit',invocation='same'),A('dispatch')])
    changed=copy.deepcopy(envelope);changed['proof']=changed['proof'][:-1]+('A' if changed['proof'][-1]!='A' else 'B')
    scenario('changed-inner-envelope',[A('submit'),A('submit',envelope=changed,verified=False),A('dispatch')])
    collision=copy.deepcopy(envelope);collision['intent']['call_id']='00000000-0000-4000-8000-000000000099';collision=sign('intent',collision['intent'])
    altered=copy.deepcopy(envelope['intent']);altered['arguments']['path']='other.txt'
    scenario('changed-valid-intent',[A('submit'),A('submit',envelope=sign('intent',altered)),A('dispatch')])
    scenario('nonce-collision',[A('submit'),A('submit',envelope=collision)])
    for when in ('reserved','executing'):
        actions=[A('submit')]+([A('dispatch')] if when=='executing' else [])+[A('crash'),A('submit'),A('dispatch'),A('complete')]
        scenario('crash-'+when,actions)
    scenario('unknown-signer-recovery',[A('submit'),A('dispatch'),A('signer',available=False),A('crash'),A('submit'),A('signer',available=True),A('submit'),A('submit')])
    scenario('terminal-persistence-failure',[A('submit'),A('dispatch'),A('complete',persistence_failure=True),A('crash'),A('submit')])
    scenario('lost-ledger',[A('submit'),A('dispatch'),A('lose-ledger'),A('crash'),A('submit'),A('recover',new_epoch='00000000-0000-4000-8000-000000000099',scope_synchronized=False),A('submit')])
    scenario('scope-recovery',[A('lose-ledger'),A('recover',trusted_admin=True,scope_synchronized=False,old_commitments_retired=True,new_mapping_durable=True,descriptor=new_policy),A('recover',trusted_admin=True,scope_synchronized=True,old_commitments_retired=True,new_mapping_durable=True,descriptor=new_policy),A('submit'),A('submit',envelope=new_envelope),A('dispatch',envelope=new_envelope),A('recover',trusted_admin=True,scope_synchronized=True,old_commitments_retired=True,new_mapping_durable=True,descriptor=new_policy)])
    scenario('client-unknown-new-id',[A('client-result',invocation='a',envelope=result('unknown')),A('client-new-call',reason='retry-unknown')],True)
    scenario('dispatch-expiry',[A('submit'),A('clock',elapsed=300),A('dispatch'),A('submit')])
    scenario('retrieval-expiry',[A('submit'),A('dispatch'),A('complete'),A('clock',elapsed=300),A('submit')])
    scenario('retrieval-revocation',[A('submit'),A('dispatch'),A('complete'),A('signer',available=False),A('submit')])
    scenario('retire-reservation',[A('submit'),A('retire'),A('dispatch'),A('submit')])
    scenario('no-rollback-after-dispatch',[A('submit'),A('dispatch'),A('retire'),A('complete'),A('submit')])
    scenario('check-load-replacement',[A('submit'),A('measure',same_immutable_instance=False,loaded_instance='artifact-B'),A('dispatch')])
    scenario('uncovered-load',[A('measure',same_immutable_instance=False,uncovered_path='extra.so'),A('submit')])
    scenario('peer-policy-install',[A('peer-provision',descriptor=policy),A('gate-failure',reason='unknown-policy'),A('submit')])
    for fault in ('skip','timeout','exception','disconnect','direct-call','signing-oracle'):
        scenario('gate-'+fault,[A('gate-failure',reason=fault),A('submit')])
    scenario('lost-clock',[A('clock-trust',trusted=False),A('submit')])
    for name,order in [('retire-first',['retire','dispatch']),('dispatch-first',['dispatch','retire'])]:
        scenario('race-'+name,[A('submit'),A('race',gate_order=[A(x) for x in order])])
    scenario('race-reserve-reject',[A('race',gate_order=[A('submit',invocation='a'),A('reject',invocation='b')]),A('dispatch')])
    scenario('race-reject-reserve',[A('race',gate_order=[A('reject',invocation='a'),A('submit',invocation='b')]),A('dispatch')])
    scenario('race-duplicate',[A('race',gate_order=[A('submit',invocation=str(n)) for n in range(8)]),A('race',gate_order=[A('dispatch') for _ in range(8)])])
    scenario('client-poll-spacing',[A('client-poll'),A('client-poll'),A('clock',elapsed=1),A('client-poll'),A('clock',elapsed=300),A('client-poll')],True)
    scenario('client-pending-terminal',[A('client-result',invocation='a',envelope=result('pending')),A('client-result',invocation='b',envelope=result()),A('client-result',invocation='c',envelope=result('pending')),A('client-result',invocation='d',envelope=result()),A('client-poll')],True)
    scenario('client-terminal-conflict',[A('client-result',invocation='a',envelope=result()),A('client-result',invocation='b',envelope=result('unknown'))],True)
    scenario('client-unsolicited',[A('client-result',invocation='missing',envelope=result()),A('client-result',invocation='a',envelope=result(),verified=False)],True)
    return fixtures
