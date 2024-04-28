import r2pipe
import json

def analysis(binary_name,input_funcs,properties):
    r2 = r2pipe.open(binary_name,flags = ["-d"])
    r2.cmd("aaa")

    functions = [func for func in json.loads(r2.cmd("aflj"))]
    input_list = []
    overflow_list = []
    used_input_func = []
    for func in functions:
        for input_func in input_funcs:
            if input_func in func['name']:
                used_input_func.append(func)
                # Get XREFs
    for func in used_input_func:
        refs = [
            func for func in json.loads(r2.cmd("axtj @ {}".format(func['name'])))
        ]
        for ref in refs:
            call_addr=ref['from']
            # if properties['pie']:
            #     call_addr+=json.loads(r2.cmd("ij"))['bin']['baddr']
            r2.cmd('db {}'.format(call_addr))
            r2.cmd('dc')
            while True:
                pc = int(r2.cmd('dr rip'), 16)  # 获取程序计数器的值
                if pc == call_addr:
                    print("Hit stop address, stopping.")
                    break
                else:
                    r2.cmd('dc')
                    print("Did not hit stop address, continuing.")
            rdi = r2.cmd('dr rdi')
            rsi = r2.cmd('dr rsi')
            rdx = r2.cmd('dr rdx')
            rbp = r2.cmd('dr rbp')
            print(rdi,rsi,rdx,rbp)
            if func['name'] == 'sym.imp.read':
                if int(rsi,16)+int(rdx,16)>int(rbp,16):
                    overflow_list.append({'addr':call_addr,'overflow_size':int(rsi,16)+int(rdx,16)-int(rbp,16),'buf_size':int(rbp,16)-int(rsi,16)})
            elif func['name'] == 'sym.imp.fgets':
                if int(rdi,16)+int(rsi,16)>int(rbp,16):
                    overflow_list.append({'addr':call_addr,'overflow_size':int(rsi,16)+int(rdi,16)-int(rbp,16),'buf_size':int(rbp,16)-int(rdi,16)})
            elif func['name'] == 'sym.imp.__isoc99_scanf':
                m = r2.cmd('psz @rdi')
                if("%s" in m):
                    overflow_list.append({'addr':call_addr,'overflow_size':0x500,'buf_size':int(rbp,16)-int(rsi,16)})
            elif func['name'] == 'sym.imp.gets':
                    overflow_list.append({'addr':call_addr,'overflow_size':0x500,'buf_size':int(rbp,16)-int(rdi,16)})
            r2.cmd("dr")
    return overflow_list
                

