import angr
from angr import sim_options as so
import logging

l = logging.getLogger(__name__)


def fully_symbolic(state, variable):
    '''
    check if a symbolic variable is completely symbolic
    '''

    for i in range(state.arch.bits):
        if not state.solver.symbolic(variable[i]):
            return False

    return True

def analysis(binary):
    p = angr.Project(binary)


    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
    es = p.factory.entry_state(add_options=extras)
    sm = p.factory.simulation_manager(es, save_unconstrained=True)

    # find a bug giving us control of PC
    l.info("looking for vulnerability in '%s'", binary)
    exploitable_state = None
    while exploitable_state is None:
        print(sm)
        sm.step()
        if len(sm.unconstrained) > 0:
            l.info("found some unconstrained states, checking exploitability")
            for u in sm.unconstrained:
                if fully_symbolic(u, u.regs.pc):
                    exploitable_state = u
                    break
            # no exploitable state found, drop them
            sm.drop(stash='unconstrained')
    l.info("found a state which looks exploitable")
    import IPython
    IPython.embed()
    return exploitable_state