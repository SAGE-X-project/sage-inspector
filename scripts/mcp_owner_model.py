"""Finite reference model only: no keys, durable storage, threads or tool effects."""
from collections import deque
from dataclasses import dataclass, replace

TIMES = (29, 30, 31, 39, 40, 49, 50, 59, 60)
EVENTS = ('setup_done', 'submit', 'reserve', 'admit', 'effect', 'finish', 'respond',
          'close', 'crash', 'invalidate') + tuple(f'tick_{t}' for t in TIMES)


@dataclass(frozen=True)
class State:
    phase: str = 'SETUP'
    operation: str = 'SETUP'
    ledger: str = 'ABSENT'
    now: int = 0
    deadline: int = 30
    admitted: bool = False
    effects: int = 0
    published: bool = False


def close(s):
    return replace(s, phase='CLOSED')


def expired(s):
    return s.now >= 60 or (s.operation in ('SETUP', 'PROTECTED') and s.now >= s.deadline)


def step(s, event):
    if event not in EVENTS:
        raise ValueError('unknown model event')
    if event.startswith('tick_'):
        now = int(event[5:])
        if now < s.now:
            return close(s)
        s = replace(s, now=now)
        return close(s) if expired(s) else s
    if event in ('close', 'invalidate'):
        return close(s)
    if event == 'crash':
        return replace(close(s), ledger='UNKNOWN' if s.ledger == 'EXECUTING' else s.ledger)
    # A committed abstract admission survives transport closure. This is not a
    # real durable transaction or proof that an external effect happened once.
    if event == 'effect':
        if s.ledger == 'EXECUTING' and s.effects == 0:
            return replace(s, effects=1)
        return s
    if event == 'finish':
        return replace(s, ledger='COMPLETED') if s.ledger == 'EXECUTING' and s.effects == 1 else s
    if s.phase == 'CLOSED':
        return s
    if expired(s):
        return close(s)
    if event == 'setup_done':
        return replace(s, phase='READY', operation='IDLE') if s.phase == 'SETUP' else s
    if event == 'submit':
        return replace(s, operation='PROTECTED', deadline=s.now + 10) if s.phase == 'READY' and s.operation == 'IDLE' else s
    if event == 'reserve':
        return replace(s, ledger='RESERVED') if s.operation == 'PROTECTED' and s.ledger == 'ABSENT' else s
    if event == 'admit':
        return replace(s, ledger='EXECUTING', admitted=True) if s.phase == 'READY' and s.operation == 'PROTECTED' and s.ledger == 'RESERVED' else s
    if event == 'respond':
        return replace(s, published=True, operation='DONE') if s.ledger == 'COMPLETED' and s.operation == 'PROTECTED' else s
    return s


def invariant(before, event, after):
    if before.phase == 'CLOSED' and after.phase != 'CLOSED':
        raise AssertionError('closed owner reopened')
    if before.ledger != 'ABSENT' and after.ledger == 'ABSENT':
        raise AssertionError('reservation lost')
    if before.admitted and not after.admitted:
        raise AssertionError('admission rolled back')
    if after.admitted and not before.admitted:
        if not (event == 'admit' and before.phase == 'READY' and before.operation == 'PROTECTED'
                and before.ledger == 'RESERVED' and before.now < before.deadline and before.now < 60):
            raise AssertionError('invalid final admission')
    if after.effects > before.effects:
        if event != 'effect' or not before.admitted or before.ledger != 'EXECUTING' or before.effects != 0:
            raise AssertionError('effect without admission or repeated')
    if not 0 <= before.effects <= after.effects <= 1:
        raise AssertionError('effect count changed incorrectly')
    if before.ledger in ('UNKNOWN', 'COMPLETED') and after.ledger != before.ledger:
        raise AssertionError('terminal outcome changed')
    if before.operation == 'PROTECTED' and after.deadline != before.deadline:
        raise AssertionError('protected deadline extended')
    if after.published and not before.published:
        if not (event == 'respond' and before.phase == 'READY' and before.ledger == 'COMPLETED'
                and before.now < before.deadline and before.now < 60):
            raise AssertionError('invalid response publication')


def explore():
    start = State()
    queue = deque([start])
    paths = {start: ()}
    transitions = 0
    witnesses = {}
    while queue:
        before = queue.popleft()
        for event in EVENTS:
            after = step(before, event)
            path = paths[before] + (event,)
            transitions += 1
            try:
                invariant(before, event, after)
            except AssertionError as error:
                raise AssertionError((str(error), path)) from error
            if after not in paths:
                if len(paths) >= 20000:
                    raise AssertionError('state bound reached; exploration incomplete')
                paths[after] = path
                queue.append(after)
            predicates = {
                'response_after_setup_deadline': event == 'respond' and not before.published and after.published and before.now > 30,
                'closed_reserved_without_effect': after.phase == 'CLOSED' and after.ledger == 'RESERVED' and not after.effects,
                'completed_after_close': before.phase == 'CLOSED' and before.ledger == 'EXECUTING' and event == 'finish' and after.ledger == 'COMPLETED',
                'crash_unknown_without_effect': after.ledger == 'UNKNOWN' and not after.effects,
            }
            for name, found in predicates.items():
                if found:
                    witnesses.setdefault(name, path)
    if len(witnesses) != 4:
        raise AssertionError('missing nonvacuous reachability witness')
    return dict(states=len(paths), transitions=transitions, witnesses=witnesses,
                clock_units=list(TIMES), setup_deadline_units=30, session_deadline_units=60,
                request_duration_units=10, state_limit=20000)
