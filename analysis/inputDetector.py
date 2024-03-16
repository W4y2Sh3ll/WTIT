import angr

stdin = "STDIN"

# Return input function list
def getInputFuncs(binary_name):

    p = angr.Project(binary_name, load_options={"auto_load_libs": False})


    # Functions which MIGHT grab from STDIN
    reading_functions = ["fgets", "gets", "scanf", "read", "__isoc99_scanf"]
    binary_functions = list(p.loader.main_object.imports.keys())

    input_list = []

    # Match reading functions against local functions
    for x in binary_functions:
        if x in reading_functions:
            input_list.append(x)
    return input_list
