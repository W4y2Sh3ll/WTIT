import r2pipe
import json

def analysis(binary_name,input_funcs):
    r2 = r2pipe.open(binary_name)
    r2.cmd("aaa")

    functions = [func for func in json.loads(r2.cmd("aflj"))]
    input_list = []
    overflow_list = []
    # Check for function that gives us system(/bin/sh)
    for func in functions:
        for input_func in input_funcs:
            if input_func in func['name']:
                # Get XREFs
                refs = [
                    func for func in json.loads(r2.cmd("axtj @ {}".format(func['name'])))
                ]
                if 'gets' in input_func:
                    for ref in refs:
                        overflow_list.append({'addr':ref['from'],'func':'gets'})
                if 'read' in input_func:
                    analysed_func=[]
                    for ref in refs:
                        if ref['fcn_name'] in analysed_func:
                            continue
                        r2.cmd("s {}".format(ref['fcn_name']))
                        analysed_func.append(ref['fcn_name'])
                        disassembly = r2.cmd("pdr").split("\n")
                        for line in disassembly[2:]:
                            if ';' in line:
                                buf_name = line.split(' ')[4]
                                buf_size = int(line.split('-')[1],16)
                                input_list.append({'name':buf_name,'buf_size':buf_size,'func':'read'})
                            else:
                                break
                        for i,line in enumerate(disassembly):
                            if '[' in line:
                                for dic in input_list:
                                    if dic['name'] in line:
                                        import IPython
                                        IPython.embed()
                                        dic['read_size']=int(disassembly[i+1].split(', ')[1].split(' ')[0],16)
                                        dic['addr']=int(disassembly[i+4].split(' ')[1],16)
                        for dic in input_list:
                            if dic['read_size']>dic['buf_size']:
                                overflow_list.append(dic)
    return overflow_list
                

