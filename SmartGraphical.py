import re
from copy import deepcopy
import difflib
import numpy as np
from IPython.display import display
import graphviz

## removes all comments of the form: /* comment */
def comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)

## replace multiple spaces with one space
def remove_extra_spaces(inp):
    return ' '.join(inp.split())

def similar_string(target_string, string_list):
    closest_match = difflib.get_close_matches(target_string, string_list, n=1, cutoff=0.6)
    return closest_match[0] if closest_match else None


def extract_requirements(bodies):
    ret = []
    for i in range(len(bodies)):
        var_inds = [m.start() for m in re.finditer('require', bodies[i])]
        ret_temp = []
        for k in range(len(var_inds)):
            eol = None
            par_iter = 0
            par_ind = bodies[i][var_inds[k]:].index('(')
            for j in range(var_inds[k]+par_ind+1,len(bodies[i])):                    
                if bodies[i][j] == ")":
                    par_iter -= 1
                if bodies[i][j] == "(":
                    par_iter += 1
                if par_iter == -1:
                    eol = j
                    break
            if bodies[i][eol+1] == ';':
                eol += 1
            temp = bodies[i][var_inds[k]:eol+1]
            # temp = temp.replace('require','').strip()
            ret_temp.append(temp)
        ret.append(ret_temp)
    # print("ret     ", ret)
    return ret
def extract_exceptions(f_body):
    var_inds = [m.start() for m in re.finditer('try', f_body)]
    # print("var inds    ", var_inds)
    try_catches = []
    for k in range(len(var_inds)):
        temp = []
        for j in range(len(f_body)):
            eol = None
            par_iter = 0
            par_ind = f_body[var_inds[k]:].index('{')
            for j in range(var_inds[k]+par_ind+1,len(f_body)):
                if f_body[j] == "}":
                    par_iter -= 1
                if f_body[j] == "{":
                    par_iter += 1
                if par_iter == -1:
                    eol = j
                    break
        # print("try phrase   ", f_body[var_inds[k]:eol+1])
        temp.append(f_body[var_inds[k]:eol+1])
        # print("rest    ", f_body[eol+1:])
        rest = f_body[eol+1:].strip()
        if rest[:len('catch')] == 'catch':
            for j in range(len(rest)):
                eol2 = None
                par_iter = 0
                par_ind = rest.index('{')
                for j in range(par_ind+1,len(rest)):
                    if rest[j] == "}":
                        par_iter -= 1
                    if rest[j] == "{":
                        par_iter += 1
                    if par_iter == -1:
                        eol2 = j
                        break
            # print("catch phrase    ", rest[:eol2+1])
            temp.append(rest[:eol2+1])
        try_catches.append(temp)
    return try_catches

def extract_asserts(bodies):
    ret = []
    for i in range(len(bodies)):
        var_inds = [m.start() for m in re.finditer('assert', bodies[i])]
        ret_temp = []
        for k in range(len(var_inds)):
            eol = None
            par_iter = 0
            par_ind = bodies[i][var_inds[k]:].index('(')
            for j in range(var_inds[k]+par_ind+1,len(bodies[i])):                    
                if bodies[i][j] == ")":
                    par_iter -= 1
                if bodies[i][j] == "(":
                    par_iter += 1
                if par_iter == -1:
                    eol = j
                    break
            if bodies[i][eol+1] == ';':
                eol += 1
            temp = bodies[i][var_inds[k]:eol+1]
            # temp = temp.replace('require','').strip()
            ret_temp.append(temp)
        ret.append(ret_temp)
    # print("ret     ", ret)
    return ret

def demonstrate_alerts(alerts):
    for i in range(len(alerts)):
        print(alerts[i])
        print("\n    ----------------------      \n")



class ContractReader:
    def __init__(self):
        self.lines = None
        self.line_sep = '--.--'    ## an indicator to show beginning of each line
        self.vars = ['string','uint','mapping','address','bytes']   ## type of variables
        self.systemic_funcs = ['Transfer', 'Approval', 'revert', 'assert', 'abi.decode','abi.encode',
                              'abi.encodeWithSelector', 'abi.encodeWithSignature','abi.encodePacked','abi.encodeCall',
                              'data.writeUint32LE','data.writeUint64LE','readInt8','readInt16LE','writeString','writeAddress',
                              'writeUint256LE','writeUint64LE','writeInt256LE','readAddress','writeInt8','writeInt32LE',
                              'addmod','mulmod',
                              '.s_feeManager','.verify']   ### systematic functions
        
        self.contracts_mem = {}

    ##  read the sol file as a string
    # params:
    # name: name of the sol file
    def read_file(self, name):
        with open(name) as f:
            lines = f.readlines()

        self.lines = lines
        return lines
    
    ##  pre-cleaning the text by removing comments and extra spaces
    # params:
    # lines: lines of the sol file
    def unify_text(self, lines):
        ###  remove_line_comments
        nc_lines = []
        for i in range(len(lines)):
            if lines[i].strip()[:2] == "//":
                continue
            if "//" in lines[i]:
                ind = lines[i].index('//')
                temp = lines[i][:ind]
                if temp[-5:] == "http:" or temp[-6:] == "https:":
                    nc_lines.append(lines[i].replace('\n',' '))
                    continue
                nc_lines.append(temp.replace('\n',' '))
                continue
            nc_lines.append(lines[i].replace('\n',' '))
        t = ' '+self.line_sep
        all_code = t.join(nc_lines)
        all_code = comment_remover(all_code)
        all_code = remove_extra_spaces(all_code)
        return all_code
    
    ##  find the end of a function, given the string starting from the beginning of that function
    # params:
    # inp: a part of the contract as a string
    def extract_func(self, inp):
        brack_iter = 0
        e_ind = None
        if '{' in inp:
            s_ind = inp.index('{')
            for i in range(s_ind+1, len(inp)):
                if inp[i] == "{":
                    brack_iter += 1
                if inp[i] == "}":
                    brack_iter -= 1
    
                if brack_iter == -1:
                    e_ind = i
                    break
        else:
            e_ind = inp.index(';')
        return inp[:e_ind+1]

    ##  extract the first tuple in the given string, used to extract input params of a function
    # params:
    # inp: a part of the contract as a string
    def extract_tuple(self, inp):
        s_ind = inp.index('(')
        e_ind = inp.index(')')
        inp = inp[s_ind+1:e_ind].strip()
        inp_params = inp.split(',')
        inp_params = [i.strip() for i in inp_params]
        ret = [i.split(' ') for i in inp_params]
        return ret


    ##  extract name and parameters of a function
    # params:
    # inp: a function as a string
    def extract_fparams(self, inp):
        ## remove body of func
        inp = inp.replace(self.line_sep,'')
        inp = ' '.join(inp.split())
        ###
        if '{' in inp:
            ind = inp.index("{")
            inp = inp[:ind]
        else:
            ind = inp.index(";")
            inp = inp[:ind]
        if '(' not in inp: ## modifier
            name = inp[:]
            name = name.replace('function','').strip()
            name = name.replace('modifier','').strip()
            return name, [], []
        s_ind = inp.index('(')
        e_ind = inp.index(')')
        ### func name
        name = inp[:s_ind]
        name = name.replace('function','').strip()
        name = name.replace('modifier','').strip()
        ### input params
        inp_params = inp[s_ind:e_ind+1].strip()
        input_details = self.extract_tuple(inp_params)
        ### returns
        rind = len(inp)
        if 'returns' in inp:
            rind = inp.index('returns')
            ret = inp[rind:]
            ret = ret.replace('returns','').strip()
            ret_params = self.extract_tuple(ret)
        ### properties
        ext_params = inp[e_ind+1:rind]
        ext_params = ext_params.strip().split(' ')
        return name, input_details, ext_params

    
    ##  extract the body of a function as a string
    # params:
    # inp: a part of the contract as a string
    def extract_body(self, inp):
        inp = inp.replace(self.line_sep,'')
        inp = ' '.join(inp.split())
        ###
        assembs = self.extract_assembly(inp)
        for i in assembs:
            inp = inp.replace(i,' ')
        ###
        if '{' in inp:
            ind = inp.index("{")
            inp = inp[ind:]
            # print("body inp    ", inp)
            ###  return
            ret_str = ''
            if 'return ' in inp or 'return(' in inp:
                rind = inp.index('return')
                ret_str = inp[rind:]
                sem_ind = ret_str.index(';')
                ret_str = ret_str[:sem_ind]
                ret_str = ret_str.replace('return','').strip()
        else:
            inp = ''
            ret_str = ''
        
        return inp, ret_str



    ##  extract all the existing contracts in a sol file
    # params:
    # inp: text of a sol file as a string
    def extract_contract(self, inp):
        # var_inds = [m.start() for m in re.finditer('contract ', inp)]
        var_inds = [m.start() for m in re.finditer(self.line_sep+'contract ', inp)]
        contracts = []
        for j in range(len(var_inds)):
            # print("sssss    ", inp[var_inds[j]-5:var_inds[j]+5])
            if inp[var_inds[j]:var_inds[j]+9] == 'contracts':
                continue
            brack_iter = 0
            start_flag = 0
            e_ind = None
            temp = inp[var_inds[j]:]
            s_ind = temp.index('{')
            for i in range(s_ind, len(temp)):
                if temp[i] == "{":
                    brack_iter += 1
                    start_flag = 1
                    continue
                if temp[i] == "}":
                    brack_iter -= 1
    
                if brack_iter == 0 and start_flag:
                    e_ind = i
                    break
            f = temp[:e_ind+1]
            contracts.append(f)
        return contracts
            

    ##  extract name and properties of a contract
    # params:
    # inp: text of a contract as a string
    def extract_contract_name(self, inp):
        ind = inp.index('contract ')
        brack_ind = inp.index('{')
        cont_inp = inp[ind:brack_ind]
        cont_inp = cont_inp.replace('contract','').strip()
        props = []
        if ' is' in cont_inp:
            temp = cont_inp.split(' is')
            temp = [i.strip() for i in temp]
            contract_name = temp[0]
            contract_props = temp[1].split(',')
            contract_props = [i.strip() for i in contract_props]
            # print("contract name    ", contract_name)
            props = contract_props
        else:
            contract_name = cont_inp
            contract_props = []
            # print("contract name    ", contract_name)
        return contract_name, props

    

    ##  extract variables and object instances inside a contract
    # params:
    # inp: contract code as a string
    # gvars: global variables types
    # obj_vars: Class definitions that might be used to create an instance.
    def extract_variables(self, inp, gvars, obj_vars):
        ret = []
        d_inp = deepcopy(inp)
        prev_vars = []
        for k in range(len(gvars)):
            t = self.line_sep+' '+gvars[k]
            gg = re.search(r'\b' + t + r'\b', inp)
            var_inds = [m.start() for m in re.finditer(t, d_inp)]
            for i in range(len(var_inds)):
                eol = None
                for j in range(var_inds[i],len(d_inp)):
                    if d_inp[j] == ";":
                        eol = j
                        break
                temp = d_inp[var_inds[i]:eol+1]
                ####
                repeat_flag = False
                for k in prev_vars:
                    if temp in k:
                        repeat_flag = True
                if repeat_flag:
                    continue
                prev_vars.append(deepcopy(temp))
                #####
                # d_inp = d_inp.replace(temp,'')
                temp = temp.replace(self.line_sep,'').strip()
                # print("temp    ", temp)
                temp = temp.replace(';','').strip()
                if '=' in temp:
                    ind = temp.index('=')
                    if temp[ind:ind+2] != '=>':
                        temp = temp[:ind]
                temp = temp.split(' ')
                temp2 = [i for i in temp if i != '']
                ret.append(temp2)
        objs = []
        for k in range(len(obj_vars)):
            t = self.line_sep+' '+obj_vars[k]
            gg = re.search(r'\b' + t + r'\b', inp)
            var_inds = [m.start() for m in re.finditer(t, inp)]
            for i in range(len(var_inds)):
                eol = None
                for j in range(var_inds[i],len(inp)):
                    if inp[j] == ";":
                        eol = j
                        break
                temp = inp[var_inds[i]:eol+1]
                temp = temp.replace(self.line_sep,'').strip()
                temp = temp.replace(';','').strip()
                if '=' in temp:
                    ind = temp.index('=')
                    if temp[ind:ind+2] != '=>':
                        temp = temp[:ind]
                temp = temp.split(' ')
                temp2 = [i for i in temp if i != '']
                objs.append(temp2)
        # print("vars      ", ret)
        return ret, objs



    ##  extract structs of a contract
    # params:
    # inp: text of a contract as a string
    def extract_structs(self, inp):
        s_inds = [m.start() for m in re.finditer('struct ', inp)]
        ret = []
        for i in range(len(s_inds)):
            brack_iter = 0
            start_flag = 0
            start_ind = 0
            e_ind = None
            temp = inp[s_inds[i]:]
            s_ind = temp.index('{')
            for i in range(s_ind, len(temp)):
                if temp[i] == "{":
                    brack_iter += 1
                    start_flag = 1
                    start_ind = i
                    continue
                if temp[i] == "}":
                    brack_iter -= 1
    
                if brack_iter == 0 and start_flag:
                    e_ind = i
                    break
            f = temp[:e_ind+1]
            f = f.replace(self.line_sep,'')
            name = f[:start_ind].replace('struct','').strip()
            body = f[start_ind:]
            ret.append([name, body])
        return ret



    ##  extract the imports in a contract
    # params:
    # inp: text of a contract as a string
    def extract_imports(self, inp):
        t = self.line_sep+'import'
        var_inds = [m.start() for m in re.finditer(t, inp)]
        ret = []
        for i in range(len(var_inds)):
            eol = None
            for j in range(var_inds[i],len(inp)):
                if inp[j] == ";":
                    eol = j
                    break
            temp = inp[var_inds[i]:eol+1]
            temp = temp.replace(self.line_sep,'').strip()
            temp = temp.replace('import','')
            temp = temp.replace(';','').strip()
            ret.append(temp)
        return ret


    ##  extract constructor of a contract
    # params:
    # inp: text of a contract as a string
    def extract_cunstructor(self, inp):
        ind = [m.start() for m in re.finditer('constructor', inp)]
        if len(ind) == 0:
            return ''
        ind = ind[0]
        inp = inp[ind:]
        brack_iter = 0
        e_ind = None
        s_ind = inp.index('{')
        for i in range(s_ind+1, len(inp)):
            if inp[i] == "{":
                brack_iter += 1
            if inp[i] == "}":
                brack_iter -= 1

            if brack_iter == -1:
                e_ind = i
                break
        f = inp[:e_ind+1]
        name, input_details, ext_params = self.extract_fparams(f)
        inp, ret_str = self.extract_body(f)
        return f



    ##  extract conditional statements in a string
    # params:
    # bodies: body of functions as a list of string
    def extract_func_conditionals(self, bodies):
        ret = []
        for i in range(len(bodies)):
            var_inds = [m.start() for m in re.finditer(' if', bodies[i])]
            ret_temp = []
            for k in range(len(var_inds)):
                eol = None
                par_iter = 0
                par_ind = bodies[i][var_inds[k]:].index('(')
                for j in range(var_inds[k]+par_ind+1,len(bodies[i])):                    
                    if bodies[i][j] == ")":
                        par_iter -= 1
                    if bodies[i][j] == "(":
                        par_iter += 1
                    if par_iter == -1:
                        eol = j
                        break
                    
                temp = bodies[i][var_inds[k]:eol+1]
                # temp = temp.replace('if','').strip()
                ret_temp.append(temp)
            ret.append(ret_temp)
        return ret



    ##  extract variable-function mapping in a contract
    # params:
    # vars: name of all variables
    # func_names: name of all functions
    # bodies: bodies of all functions as a list of strings
    def extract_var_func_mapping(self, vars, func_names, bodies):
        ret = {}
        for i in vars:
            ret[i] = []
        for i in range(len(vars)):
            for j in range(len(bodies)):
                if vars[i] in bodies[j]:
                    # print("vvvv    ", vars[i])
                    # print("bbbb    ", bodies[j])
                    var_inds = [m.start() for m in re.finditer(vars[i], bodies[j])]
                    for k in range(len(var_inds)):
                        if var_inds[k] > 0:
                            if bodies[j][var_inds[k]-1] == '_':
                                continue
                        if bodies[j][var_inds[k]+len(vars[i])] == '(':
                            continue
                        if not (bodies[j][var_inds[k]+len(vars[i])] == " " or 
                                bodies[j][var_inds[k]+len(vars[i])] == "=" or bodies[j][var_inds[k]+len(vars[i])] == "[" or bodies[j][var_inds[k]+len(vars[i])] == ";"):
                            continue
                        if ret[vars[i]].count(func_names[j]) == 0:
                            ret[vars[i]].append(func_names[j])
        return ret


    ##  extract function-function mapping in a contract
    # params:
    # func_names: name of all functions
    # bodies: bodies of all functions as a list of strings
    def extract_func_func_mapping(self, func_names, bodies):
        ret = {}
        for i in func_names:
            ret[i] = []
        for i in range(len(func_names)):
            for j in range(len(bodies)):
                if func_names[i]+'(' in bodies[j] and not '_'+func_names[i] in bodies[j]:
                    if i == j:
                        ret[func_names[i]].append('super.'+func_names[j])
                    else:
                        if ret[func_names[i]].count(func_names[j]) == 0:
                            ret[func_names[i]].append(func_names[j])
        return ret


    ##  extract function-function mapping a contract and its parent contract(class)
    # params:
    # func_names_parent: name of all functions in the parent contract
    # func_names: name of all functions
    # bodies: bodies of all functions as a list of strings
    def extract_intra_func_func_mapping(self, func_names_parent, func_names, bodies):
        ret = {}
        for i in func_names_parent:
            ret[i] = []
        for i in range(len(func_names_parent)):
            for j in range(len(bodies)):
                if func_names_parent[i]+'(' in bodies[j] and not '_'+func_names_parent[i] in bodies[j]:
                    if ret[func_names_parent[i]].count(func_names[j]) == 0:
                        ret[func_names_parent[i]].append(func_names[j])
        return ret



    ##  extract system_function-function mapping in a contract
    # params:
    # func_names: name of all functions
    # bodies: bodies of all functions as a list of strings
    def extract_sysfunc_func_mapping(self, func_names, bodies):
        ret = {}
        for i in self.systemic_funcs:
            ret[i] = []
        for i in range(len(self.systemic_funcs)):
            for j in range(len(bodies)):
                if self.systemic_funcs[i]+'(' in bodies[j] and not '_'+self.systemic_funcs[i] in bodies[j]:
                    if ret[self.systemic_funcs[i]].count(func_names[j]) == 0:
                        ret[self.systemic_funcs[i]].append(func_names[j])
        return ret


    ##  extract using statements in a contract
    # params:
    # cont_code: text of a contract as a string
    def extract_using(self, cont_code):
        ret = []
        if 'using' in cont_code:
            ind = cont_code.index('using')
            temp = cont_code[ind:]
            eol = temp.index(';')
            temp = temp[:eol+1]
            r = temp.split(' ')
            ret.append(r)
        return ret


    ##  Extract all interfaces from a contract
    # params:
    # inp: text of a contract as a string
    def extract_interface(self, inp):
        var_inds = [m.start() for m in re.finditer('interface ', inp)]
        interfaces = []
        for j in range(len(var_inds)):
            if inp[var_inds[j]:var_inds[j]+10] == 'interfaces':
                continue
            brack_iter = 0
            start_flag = 0
            e_ind = None
            temp = inp[var_inds[j]:]
            s_ind = temp.index('{')
            for i in range(s_ind, len(temp)):
                if temp[i] == "{":
                    brack_iter += 1
                    start_flag = 1
                    continue
                if temp[i] == "}":
                    brack_iter -= 1
    
                if brack_iter == 0 and start_flag:
                    e_ind = i
                    break
            f = temp[:e_ind+1]
            f = f.replace(self.line_sep, '')
            interfaces.append(f)
        return interfaces


    ##  Extract all events from a contract
    # params:
    # inp: text of a contract as a string
    def extract_events(self, inp):
        s_inds = [m.start() for m in re.finditer('event ', inp)]
        ret = []
        details = []
        for i in range(len(s_inds)):
            brack_iter = 0
            start_flag = 0
            start_ind = 0
            e_ind = None
            temp = inp[s_inds[i]:]
            s_ind = temp.index('(')
            for i in range(s_ind, len(temp)):
                if temp[i] == ";":
                    e_ind = i
                    break
            f = temp[:e_ind+1]
            name = f[:s_ind].replace('event','').strip()
            params = f[s_ind:]
            details.append([name,params])
            ret.append(f)
        return ret, details



    ##  extract obj-function mapping in a contract
    # params:
    # objs: name of all previously defined contracts(classes)
    # func_names: name of all functions
    # bodies: bodies of all functions as a list of strings
    def extract_obj_func_mapping(self, objs, func_names, bodies):
        ret = {}
        for i in objs:
            ret[i] = []
        for i in range(len(objs)):
            for j in range(len(bodies)):
                if objs[i] in bodies[j]:
                    var_inds = [m.start() for m in re.finditer(objs[i], bodies[j])]
                    for k in range(len(var_inds)):
                        if var_inds[k] > 0:
                            if bodies[j][var_inds[k]-1] == '_':
                                continue
                        if bodies[j][var_inds[k]+len(objs[i])] == '(':
                            continue
                        if not (bodies[j][var_inds[k]+len(objs[i])] == "."):
                            continue
                        ## find func
                        e_ind = bodies[j][var_inds[k]:].index('(')
                        obj_func_name = bodies[j][var_inds[k]+len(objs[i])+1: var_inds[k]+e_ind]
                        if ret[objs[i]].count([func_names[j], obj_func_name]) == 0:
                            ret[objs[i]].append([func_names[j], obj_func_name])
        return ret

    ##  Extract assembly from a body
    # params:
    # inp: text of a function body as a string
    def extract_assembly(self, inp):
        var_inds = [m.start() for m in re.finditer('assembly ', inp)]
        assembs = []
        for j in range(len(var_inds)):
            brack_iter = 0
            start_flag = 0
            e_ind = None
            temp = inp[var_inds[j]:]
            s_ind = temp.index('{')
            for i in range(s_ind, len(temp)):
                if temp[i] == "{":
                    brack_iter += 1
                    start_flag = 1
                    continue
                if temp[i] == "}":
                    brack_iter -= 1
    
                if brack_iter == 0 and start_flag:
                    e_ind = i
                    break
            f = temp[:e_ind+1]
            assembs.append(f)
        return assembs
    

    ##  Extract all necesssary data from the solidity file
    # params:
    # all_code: text of the solidity file as a string
    def __call__(self, all_code):
        analyzed_contracts = []
        #####  extract contracts
        contracts = self.extract_contract(all_code)
        # print(" ****   len contracts    ", len(contracts))
        ########  interfaces
        interfaces = self.extract_interface(all_code)
        # print("--------------   interface   -------------")
        # print(interfaces)
        # print("------------------------------------------")
        ##
        interf = [i.replace('interface','contract') for i in interfaces]
        contracts.extend(interf)
        #######  extract data from each contract
        ret = []
        hierarchy = {}
        for i in range(len(contracts)):
            funcs = []
            cont_code = contracts[i]
            ## extract using
            using = self.extract_using(cont_code)
            ## extract structs
            structs = self.extract_structs(cont_code)
            ## find beginning of functions in the string
            func_inds = [m.start() for m in re.finditer('function ', cont_code)]
            ## find beginning of modifiers in the string
            modif_inds = [m.start() for m in re.finditer('modifier ', cont_code)]
            func_inds.extend(modif_inds)
            ## extract details of each function and modifier
            res_code = deepcopy(cont_code)
            for i in range(len(func_inds)):
                f = self.extract_func(cont_code[func_inds[i]:])
                res_code = res_code.replace(f,' ')
                # print("f    ", f)
                name, input_details, ext_params = self.extract_fparams(f)
                body, ret_str = self.extract_body(f)
                funcs.append([name, input_details, ext_params, body])
            ####  extract name and properties of teh contract
            # print("cont code    ", cont_code)
            contract_name, parents = self.extract_contract_name(cont_code)
            hierarchy[contract_name] = parents
            #
            self.contracts_mem[contract_name] = {}
            self.contracts_mem[contract_name]['funcs'] = deepcopy(funcs)
            #### extract constructor of the contract
            f = self.extract_cunstructor(cont_code)
            if len(f) > 0:
                res_code = res_code.replace(f,' ')
                name, input_details, ext_params = self.extract_fparams(f)
                body, ret_str = self.extract_body(f)
                constructor = [name, input_details, ext_params, body]
            else:
                constructor = []
            #############
            ## extract and remove events
            events, evt_details = self.extract_events(res_code)
            for ev in events:
                res_code = res_code.replace(ev,' ')
            ############
            ##  extract variables and object instances in a contract
            vars, objs = self.extract_variables(res_code, self.vars, analyzed_contracts)
            ## extract imports
            imps = self.extract_imports(res_code)
            ####  prepare data for extracting mappings
            var_names = [i[-1] for i in vars]
            var_names.extend([i[0] for i in structs])
            ##
            func_names = [i[0] for i in funcs]
            func_bodies = [i[3] for i in funcs]
            if len(constructor) == 1:
                func_names.extend([constructor[0]])
                func_bodies.extend([constructor[-1]])
            #
            for dt in evt_details:
                func_names.append(dt[0])
                func_bodies.append('')
            # print("func names     ", func_names)
            ## extract variable-function mapping
            var_func_mapping = self.extract_var_func_mapping(var_names, func_names, func_bodies)
            ## extract function-function mapping
            func_func_mapping = self.extract_func_func_mapping(func_names, func_bodies)
            sysfunc_func_mapping = self.extract_sysfunc_func_mapping(func_names, func_bodies)
            ## extract object-function mapping
            obj_names = [i[-1] for i in objs]
            obj_func_mapping = self.extract_obj_func_mapping(obj_names, func_names, func_bodies)
            ####  extract conditionals
            func_conditionals = self.extract_func_conditionals(func_bodies)
            ####
            analyzed_contracts.append(contract_name)
            #### add data to the return values
            ret.append([contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, evt_details, objs, using])
        ############
        ###  Find connections between multiple contracts
        all_contract_names = list(hierarchy.keys())
        # print("all contract names    ", all_contract_names)
        # print("hierarchy     ", hierarchy)
        high_connections = []
        for k,v in hierarchy.items():
            if len(v) == 0:
                continue
            for j in range(len(v)):
                parent_cont = v[j]
                child_cont = k
                if parent_cont not in all_contract_names:
                    continue
                parent_ind = all_contract_names.index(parent_cont)
                child_ind = all_contract_names.index(child_cont)
                ###
                var_temp = ret[parent_ind][2]
                vars = [k[-1] for k in var_temp]
                func_temp = ret[child_ind][1]
                func_names = [k[0] for k in func_temp]
                func_bodies = [k[3] for k in func_temp]
                # extract variable-function mapping
                var_func_mapping = self.extract_var_func_mapping(vars, func_names, func_bodies)
                func_temp2 = ret[parent_ind][1]
                func_names_parent = [k[0] for k in func_temp2]
                # extract function-function mapping
                func_func_mapping = self.extract_intra_func_func_mapping(func_names_parent, func_names, func_bodies)

                conn = {'parent': parent_cont, 'child': child_cont, 'var_func_mapping': var_func_mapping, 'func_func_mapping': func_func_mapping}
                high_connections.append(conn)
        ###  Find connections between contracts and interfaces
        int_len = len(interfaces)
        # print("int len    ", int_len)
        if int_len > 0:
            scaned_int = ret[-int_len:]
        else:
            scaned_int = []
        # print("temp names   ", [i[0] for i in ret])
        for i in range(len(contracts)):
            for j in range(len(scaned_int)):
                if scaned_int[j][0] in contracts[i]:
                    parent_cont = scaned_int[j][0]
                    child_cont = ret[i][0]
                    ##
                    if parent_cont not in all_contract_names:
                        continue
                    parent_ind = all_contract_names.index(parent_cont)
                    child_ind = all_contract_names.index(child_cont)
                    ###
                    var_temp = ret[parent_ind][2]
                    vars = [k[-1] for k in var_temp]
                    func_temp = ret[child_ind][1]
                    func_names = [k[0] for k in func_temp]
                    func_bodies = [k[3] for k in func_temp]
                    var_func_mapping = self.extract_var_func_mapping(vars, func_names, func_bodies)
                    func_temp2 = ret[parent_ind][1]
                    func_names_parent = [k[0] for k in func_temp2]
                    func_func_mapping = self.extract_intra_func_func_mapping(func_names_parent, func_names, func_bodies)
    
                    conn = {'parent': parent_cont, 'child': child_cont, 'var_func_mapping': var_func_mapping, 'func_func_mapping': func_func_mapping}
                    high_connections.append(conn)
        
        # print("**************    ", high_connections)
        return ret, hierarchy, high_connections

#####################################################################
#####################################################################
#####################################################################
#####################################################################
#####################################################################
#####################################################################
#####################################################################

# import argparse
# parser = argparse.ArgumentParser()

# parser.add_argument('--contract_name', default='default')

import sys

if len(sys.argv) != 2:
    print("Error: Please provide a Solidity filename as an argument (ex: python SmartgGraphical.py contract1.sol)")
    sys.exit(1)
if not sys.argv[1]:
    print("Error: Filename cannot be empty or None.")
    sys.exit(1)
filename = sys.argv[1]


reader = ContractReader()
# filename = 'contract2.sol'
# filename = 'Theta.sol'
# filename = 'yaml.sol'
# filename = 'contract5.sol'
# filename = 'contract6.sol'
# filename = 'contract7.sol'
# filename = 'contract_rebase.sol'
# filename = 'contract_supp.sol'
# filename = 'contract8.sol'
# filename = 'contract_trycatch.sol'
ln = reader.read_file(filename)
# print("ln   ", ln)
unified_code = reader.unify_text(ln)
rets, hierarchy, high_connections = reader(unified_code)




help = " ------------------------------------------------------------------\n \
   Help:\n \
\n Task 1: The signatures associated with the function definitions in every function of the smart contract code must be examined and updated if the contract is the outcome of a rewrite or update of another contract. If this isn't done, the contract may have a logical issue, and information from the previous signature may be given to the functions using the programmer\'s imagination. This inevitably indicates that the contract code contains a runtime error.\n \
-----\n\
Task 2: In the event that the developer modifies contract parameters, such as the maximum fee or user balance, or other elements, like totalSupply, that are determined by another contract. This could be risky and result in warnings being generated. Generally speaking, obtaining any value from a source outside the contract may have a different value under various circumstances, which could lead to a smart contract logical error. For instance, the programmer might not have incorporated the input's fluctuation or range into the program logic\n \
-----\n\
Task 3: The quantity of collateral determines one of the typical actions in DeFi smart contracts, in addition to stake and unstake. Attacks like multiple borrowing without collateral might result from logical mistakes made by the developer when releasing this collateral, determining the maximum loan amount that can be given, and determining the kind and duration of the collateral encumbrance\n \
-----\n\
Tasks 3 and 5 and 9: When a smart contract receives value, like financial tokens or game points (from staking assets, depositing points, or depositing tokens), it must perform a logical check when the assets are removed from the system to ensure that no user can circumvent the program's logic and take more money out of the contract than they are actually entitled to. \n \
-----\n\
Tasks 2 and 4: All token supply calculations must be performed accurately and completely. Even system security and authentication might be taken into account, but the communication method specification is entirely incorrect. For instance, one of the several errors made by developers has been the presence of a function like burn that can remove tokens from the pool or functions identical to it that can add tokens to the pool. To determine whether this is necessary in terms of program logic and whether other supply changes are taken into account in this computation, these conditions should be looked at. No specific function is required, and burning tokens can be moved to an address as a transaction without being returned. \n \
-----\n\
Task 2 and 5 and 9: There are various incentive aspects in many smart contracts that defy logic. For instance, if the smart contract has a point system for burning tokens, is it possible to use that point in other areas of the contract? It is crucial to examine the income and spending points in this situation. For instance, the developer can permit spending without making sure the user validates the point earning. The program logic may be abused as a result of this. \n \
-----\n\
Task 6: The code's error conditions need to be carefully examined. For instance, a logical error and a serious blow to the smart contract can result from improperly validating the error circumstances. Assume, for instance, that the programmer uses a system function to carry out a non-deterministic transport, but its error management lacks a proper understanding of the system state. In the event of an error, for instance, the coder attempts to reverse the system state; however, this may not be logically sound and could result in misuse of the smart contract by, for instance, reproducing an unauthorized activity in the normal state. \n \
-----\n\
Task 7: Logical errors can result from any complicated coding calculations. For instance, a cyber attacker may exploit the program logic by forcing their desired computation output if the coder fails to properly analyze the code output under various scenarios. \n \
-----\n\
Tasks 8 and 9: A smart contract's execution output might be impacted by the sequence in which certain procedures are carried out. The developer measuring or calculating the price of a token (or anything similar) and then transferring the asset at a certain time period is one of the most prevalent examples of this kind of vulnerability. Given that the attacker can manipulate the market through fictitious fluctuations, this is a logical issue. Thus, this gives the attacker the ability to remove the asset from the agreement. \n \
-----\n\
Task 10: In a smart contract, using names that are spelled similarly to one another may cause logical issues. For instance, the coder might inadvertently substitute one of these definitions for another in the contract, which would be undetectable during the coder's initial tests. There is a chance that a cybercriminal will take advantage of this scenario. \n \
-----\n\
Task 11: A smart contract's function that can be called fully publicly and without limitations may be risky and necessitate additional research from the developer if it modifies variables, delivers inventory, or does something similar\n \
 -------------------------------------------------------------------------------\n\
"

print(help)

task = input('\n 1: Old version\n \
2: Unallowed manipulation\n \
3: Stake function\n \
4: Pool interactions\n \
5: Local points\n \
6: Exceptions\n \
7: Complicated calculations\n \
8: Order of calls\n \
9: Withdraw actions\n \
10: Similar names\n \
11: Outer calls\n \
12: Graphical demonstration\n \
13: Run all tasks\n \
Enter task number:  ')
print("task    ", task)


######################################################
## Task 1, contract version
# var_inds = [m.start() for m in re.finditer(t, inp)]

def comment_extractor(lines):
    all_comments = []
    nc_lines = []
    for i in range(len(lines)):
        if lines[i].strip()[:2] == "//":
            all_comments.append(lines[i])
            continue
        if "//" in lines[i]:
            ind = lines[i].index('//')
            temp = lines[i][:ind]
            if temp[-5:] == "http:" or temp[-6:] == "https:":
                nc_lines.append(lines[i].replace('\n',' '))
                continue
            nc_lines.append(temp.replace('\n',' '))
            continue
        nc_lines.append(lines[i].replace('\n',' '))
    t = ' '+ reader.line_sep
    all_code = t.join(nc_lines)
    ##
    def replacer(match):
        # print("match    ", match.group(0))
        s = match.group(0)
        all_comments.append(s)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(
        # r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        r'/\*.*?\*/',
        re.DOTALL | re.MULTILINE
    )
    clean_code = re.sub(pattern, replacer, all_code)
    return all_comments
# print("ln   ", ln)

def contract_version():
    alerts = []
    comments = comment_extractor(ln)
    # print(comments)
    var_list = [" version "," new "," old "]
    for i in range(len(comments)):
        # print("comments[i]     ", comments[i])
        for j in range(len(var_list)):
            if var_list[j] in comments[i]:
                # print("key word    ", var_list[j])
                # print("comment    ", comments[i].replace(reader.line_sep,' '))
                com = comments[i].replace(reader.line_sep,' ')
                alerts.append({
                    'code':1, 
                    'message': f"Alert: keyword '{var_list[j]}' used in comment '{com}'"
                })
            # print("------------------------------------------------------------")
    return alerts

#################################################################
# task 2

def unallowed_manipulation():
    alerts = []
    all_vars = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("vars   ", vars)
        dvars = deepcopy(vars)
        x = [i.insert(0,contract_name) for i in dvars]
        all_vars.extend(dvars)
    # print("vars    ", all_vars)
    unallowed_vars = ['totalSupply', 'balance', 'fee']
    for idx, una_var in enumerate(unallowed_vars):
        # print(" ------------------------------------------      ", una_var)
        current_var_name = ''
        var_default_name = una_var #'totalSupply'
        var_names = [i[-1] for i in all_vars]
        # print("var names    ", var_names)
        corresponding_contract = None
        if var_default_name in var_names:
            if var_names.count(var_default_name) > 1:
                # print("    ---  warning  ---    ")
                # print("multiple definitions of total supply")
                alerts.append({
                    'code':2, 
                    'message': f"Alert: multiple definitions of total supply"
                })
                ind = var_names.index(var_default_name)
                corresponding_contract = all_vars[ind][0]
                # current_var_name = 'totalSupply'
                current_var_name = var_names[ind]
            else:
                ind = var_names.index(var_default_name)
                # print("ind    ", ind)
                corresponding_contract = all_vars[ind][0]
                # print("corresponding contract    ", corresponding_contract)
                # current_var_name = 'totalSupply'
                current_var_name = var_names[ind]
        else:
            sim = similar_string(una_var, var_names)
            if sim is None:
                # print(f"No similar variable was found for {una_var}")
                continue
            else:
                current_var_name = sim
                ind = var_names.index(current_var_name)
                corresponding_contract = all_vars[ind][0]
        #######
        # print("current var name    ", current_var_name)
        # print("corresponding contract    ", corresponding_contract)
        prev_alerts = []
        prev_reqs = []
        if corresponding_contract is not None:
            susceptible_vars = [current_var_name, 'supply', 'amount', 'fee']
            funcs = reader.contracts_mem[corresponding_contract]['funcs']
            bodies = [i[-1] for i in funcs]
            # print("bodies    ", bodies)
            for sus in susceptible_vars:
                for bb in range(len(bodies)):
                    # print("body     ", bodies[bb])
                    # t = tot_sup_name
                    t = sus
                    var_inds = [m.start() for m in re.finditer(t, bodies[bb])]
                    # print("var inds    ", var_inds)
                    for i in range(len(var_inds)):
                        bol = None
                        for j in range(var_inds[i],0,-1):
                            if bodies[bb][j] == ";":
                                bol = j+1
                                break
                        if bol is None:
                            bol = 1
                        #######
                        eol = None
                        for j in range(var_inds[i],len(bodies[bb])):
                            if bodies[bb][j] == ";":
                                eol = j
                                break
                        # print("eol    ", eol)
                        if eol is None:
                            eol = len(bodies[bb])-1
                        # print("beol     ", bol, " -  ", eol)
                        # temp = bodies[bb][var_inds[i]:eol+1]
                        temp = bodies[bb][bol:eol+1]
                        # print("temp    ", temp)
                        temp = temp.replace(reader.line_sep,'').strip()
                        # temp = temp.replace(';','').strip()
                        if "require" in temp:
                            # print(f"Requirement for '{sus}' variable")
                            # alerts.append({
                            #     'code':2, 
                            #     'message': f"Alert: Requirement for '{sus}' variable in line: {temp}"
                            # })
                            if temp not in prev_reqs:
                                prev_reqs.append(temp)
                            continue
                        elif ('+' in temp) or ('+=' in temp) or ('-' in temp) or ('-=' in temp):
                            # print("body     ", bodies[bb])
                            pass
                            # print("--------")
                            # print(f"Some value has been manipulated for {sus}")
                            # print("Line:    ", temp)
                            # print("--------")
                        elif '=' in temp:
                            # print("body     ", bodies[bb])
                            ind = temp.index('=')
                            if temp[ind:ind+2] != '=>':
                                pass
                                # print("--------")
                                # print(f"Some value has been assigned to {sus}")
                                # print("Line:    ", temp)
                                # print("--------")
                        for f_par in range(len(funcs[bb][1])):
                            # print("fpar    ", funcs[bb][1][f_par])
                            if len(funcs[bb][1][f_par]) > 1:
                                if funcs[bb][1][f_par][1] in temp:
                                    if [sus,temp] in prev_alerts:
                                        continue
                                    ####
                                    req_flag = False
                                    for req_var in prev_reqs:
                                        if sus in req_var:
                                            req_flag = True
                                    if req_flag:
                                        continue
                                    ####
                                    if "after" in temp and "transfer" in temp:
                                        continue
                                    if "before" in temp and "transfer" in temp:
                                        continue
                                    ####
                                    if "return " in temp or "require(" in temp:
                                        continue
                                    prev_alerts.append([sus,temp])
                                    # print("--------")
                                    # print(f"Alert: Some value has been assigned to {sus} from function inputs")
                                    # print("Line:    ", temp)
                                    # print("--------")
                                    alerts.append({
                                        'code':2, 
                                        'message': f"Alert: Some value has been assigned to {sus} from function inputs in line: {temp}"
                                    })
    return alerts


####################################################
# task 3

def extract_operation(var, body):
    # print("var    ", var)
    # print("body    ", body)
    ret = []
    var_inds = [m.start() for m in re.finditer(var, body)]
    for i in range(len(var_inds)):
        bol = None
        for j in range(var_inds[i],0,-1):
            if body[j] == ";":
                bol = j
                break
        eol = None
        for j in range(var_inds[i],len(body)):
            if body[j] == ";":
                eol = j
                break
        temp = body[bol:eol+1]
        ret.append(temp[1:])
        # print(" ---  temp    ", temp[1:])
    #### 
    # for i in range(len(ret)):
    #     # print("ret i    ", ret[i])
    #     # print("sg    ", '+' in ret[i])
    #     if ('+' in ret[i]) or ('+=' in ret[i]):
    #         print("manipulation line    ", ret[i])
    #     if ('-' in ret[i]) or ('-=' in ret[i]):
    #         print("manipulation line    ", ret[i])
    return ret

def staking():
    alerts = []
    all_vars = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("contract name       ", contract_name)
        # print("funcs    ", funcs)
        # print("funcs    ", [i[0] for i in funcs])
        # print("vars   ", vars)
        temp = deepcopy(funcs)
        [i.insert(0,contract_name) for i in temp]
        all_vars.extend(temp)
    # print("all vars    ", all_vars)
    #####
    ## func [cont_name, name, input_details, ext_params, body]
    stake_vars = ['stake']
    stake_func_name = None
    for stk in stake_vars:
        for i in range(len(all_vars)):
            reqs = extract_requirements([all_vars[i][-1]])
            new_body = deepcopy(all_vars[i][-1])
            for j in range(len(reqs[0])):
                new_body = all_vars[i][-1].replace(reqs[0][j], '')
            # var_inds = [m.start() for m in re.finditer(' '+stk, all_vars[i][-1])]
            var_inds = [m.start() for m in re.finditer(' '+stk, new_body)]
            # print("**********")
            # print("var inds    ", var_inds)
            # for jj in var_inds:
            #     print("body   ", all_vars[i][-1][jj-5: jj+len(stk)+5])
            # print("**********")
            # if stk in all_vars[i][-1]:
            if len(var_inds) > 0:
                # print(f"Variable '{stk}' is used in '{all_vars[i][0]}' contract, '{all_vars[i][1]}' function.")
                alerts.append({
                    'code':3, 
                    'message': f"Variable '{stk}' is used in '{all_vars[i][0]}' contract, '{all_vars[i][1]}' function."
                })
            if stk in all_vars[i][1]:
                # print(f"Function '{all_vars[i][1]}' is related to '{stk}' in '{all_vars[i][0]}' contract.")
                alerts.append({
                    'code':3, 
                    'message': f"Function '{all_vars[i][1]}' is related to '{stk}' in '{all_vars[i][0]}' contract."
                })
                if stk == 'stake' and stake_func_name is None:
                    # print("1")
                    stake_func_name = [all_vars[i][1], all_vars[i][2], all_vars[i][4]]
    # print("stake func name   ", stake_func_name)
    if stake_func_name is None:
        # print("No stake function found, skipping the process.")
        return alerts
    ###
    unstake_func_name = None
    unstake_vars = ['unstake']
    for stk in unstake_vars:
        for i in range(len(all_vars)):
            reqs = extract_requirements([all_vars[i][-1]])
            new_body = deepcopy(all_vars[i][-1])
            for j in range(len(reqs[0])):
                new_body = all_vars[i][-1].replace(reqs[0][j], '')
            # var_inds = [m.start() for m in re.finditer(' '+stk, all_vars[i][-1])]
            var_inds = [m.start() for m in re.finditer(' '+stk, new_body)]
            # print("**********")
            # print("var inds    ", var_inds)
            # for jj in var_inds:
            #     print("body   ", all_vars[i][-1][jj-5: jj+len(stk)+5])
            # print("**********")
            # if stk in all_vars[i][-1]:
            if len(var_inds) > 0:
                # print(f"Variable '{stk}' is used in '{all_vars[i][0]}' contract, '{all_vars[i][1]}' function.")
                alerts.append({
                    'code':3, 
                    'message': f"Variable '{stk}' is used in '{all_vars[i][0]}' contract, '{all_vars[i][1]}' function."
                })
            if stk in all_vars[i][1]:
                # print(f"Function '{all_vars[i][1]}' is related to '{stk}' in '{all_vars[i][0]}' contract.")
                alerts.append({
                    'code':3, 
                    'message': f"Function '{all_vars[i][1]}' is related to '{stk}' in '{all_vars[i][0]}' contract."
                })
                if stk == 'unstake' and unstake_func_name is None:
                    # print("2")
                    unstake_func_name = [all_vars[i][1], all_vars[i][2], all_vars[i][4]]
    # print("unstake func name   ", unstake_func_name)
    if stake_func_name is not None and unstake_func_name is None:
        # print("No unstake function provided, while staking function exists.")
        alerts.append({
            'code':3, 
            'message': "No unstake function provided, while staking function exists."
        })
    ####
    # find manipulation line in body
    if stake_func_name is not None:
        stake_man = extract_operation(stake_func_name[1][0][-1], stake_func_name[2])
        for i in range(len(stake_man)):
            # print("ret i    ", ret[i])
            if ('+' in stake_man[i]) or ('+=' in stake_man[i]):
                # print(" ------ ")
                # print("manipulation line:    ", stake_man[i])
                # print("stake function:    ", stake_func_name[0])
                # print(" ------ ")
                alerts.append({
                    'code':3, 
                    'message': f"In stake function {stake_func_name[0]}, Manipulation in line '{stake_man[i]}'."
                })
            # if ('-' in stake_man[i]) or ('-=' in stake_man[i]):
            #     print("manipulation line    ", stake_man[i])
            #     print("unstake function:    ", stake_func_name[0])
    
    if unstake_func_name is not None:
        unstake_man = extract_operation(unstake_func_name[1][0][-1], unstake_func_name[2])
        for i in range(len(stake_man)):
            # print("ret i    ", ret[i])
            # if ('+' in stake_man[i]) or ('+=' in stake_man[i]):
            #     print("manipulation line:    ", stake_man[i])
            #     print("stake function:    ", stake_func_name[0])
            if ('-' in unstake_man[i]) or ('-=' in unstake_man[i]):
                # print(" ------ ")
                # print("manipulation line    ", unstake_man[i])
                # print("unstake function:    ", unstake_func_name[0])
                # print(" ------ ")
                alerts.append({
                    'code':3, 
                    'message': f"In stake function {unstake_func_name[0]}, Manipulation in line '{unstake_man[i]}'."
                })
    return alerts

######################################################
## Task 4

def pool_interactions():
    alerts = []
    all_funcs = []
    all_conditionals = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("conditionals   ", func_conditionals)
        dvars = deepcopy(funcs)
        x = [i.insert(0,contract_name) for i in dvars]
        # print("dvars    ", dvars)
        all_funcs.extend(dvars)
        all_conditionals.extend(func_conditionals)
    #############
    # print("funcs    ", all_funcs[0])
    mint_names = ["mint"]
    for idx, var in enumerate(mint_names):
        for j in range(len(all_funcs)):
            if var in all_funcs[j][1]:
                # print("mint function    ", all_funcs[j])
                # print("----------")
                if 'external' in all_funcs[j][3]:
                    flag = True
                    for k in all_funcs[j][3]:
                        if 'only' in k:
                            flag = False

                    if flag:
                        alerts.append({
                            'code':4, 
                            'message': f"Alert: Mint function is external"
                        })
                if len(all_conditionals[j]) > 0:
                    for c in all_conditionals[j]:
                        # print(f"Mint function: Condition: {c}")
                        alerts.append({
                            'code':4, 
                            'message': f"Mint function: Condition: {c}"
                        })
                # print("----------")
    ###############
    burn_names = ["burn"]
    for idx, var in enumerate(burn_names):
        for j in range(len(all_funcs)):
            if var in all_funcs[j][1]:
                # print("Burn function    ", all_funcs[j])
                # print("Burn function body   ", all_funcs[j][4])
                # print("----------")
                if 'external' in all_funcs[j][3]:
                    
                    # print("Alert: Burn function is external")
                    alerts.append({
                        'code':4, 
                        'message': f"Alert: Burn function is external"
                    })
                for k in all_funcs[j][3]:
                    if 'only' in k:
                        # print(f"Burn function has special permissions: {k}")
                        # alerts.append({
                        #     'code':4, 
                        #     'message': f"Burn function has special permissions: {k}"
                        # })
                        pass
                if len(all_conditionals[j]) > 0:
                    for c in all_conditionals[j]:
                        # print(f"Burn Condition: {c}")
                        alerts.append({
                            'code':4, 
                            'message': f"Burn Condition: {c}"
                        })
                # print("----------")
                ###
                lines = all_funcs[j][4].split(";")
                for ln in lines:
                    if 'address(0)' in ln:
                        # print(f"zero address is used in line: {ln}")
                        alerts.append({
                            'code':4, 
                            'message': f"zero address is used in line: {ln}"
                        })
    return alerts

############################################################
## Task 5, 

def local_points():
    alerts = []
    for i in range(len(rets)):
        all_funcs = []
        all_conditionals = []
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("conditionals   ", func_conditionals)
        dvars = deepcopy(funcs)
        x = [i.insert(0,contract_name) for i in dvars]
        # print("dvars    ", dvars)
        all_funcs.extend(dvars)
        all_conditionals.extend(func_conditionals)
        contract_vars = [i[-1] for i in vars]
        # print("contract vars     ", contract_vars)
        # print("structs    ", structs)
        contract_structs = [i[0] for i in structs]
        # print("contract structs    ", contract_structs)
        contract_vars.extend(contract_structs)
        #############
        # print("funcs    ", all_funcs[0])
        recieve_names = ["recieve", "take", "burn","allowance","balance","point"]
        unallowed = ["stake", "unstake"]
        for idx, var in enumerate(recieve_names):
            for j in range(len(all_funcs)):
                if (var in all_funcs[j][1]):
                    unl_flag = False
                    for k in unallowed:
                        if k in all_funcs[j][1]:
                            unl_flag = True
                    if unl_flag:
                        continue
                    # print("reieve function    ", all_funcs[j])
                    # print("----------")
                    reqs = extract_requirements([all_funcs[j][4]])[0]
                    # print("reqs    ", reqs)
                    vars_to_check = ['allowance','balance','point']
                    for vc in range(len(vars_to_check)):
                        if vars_to_check[vc] not in contract_vars:
                            continue
                        flag = True
                        for r in range(len(reqs)):
                            if vars_to_check[vc] in reqs[r]:
                                flag = False
                        if flag:
                            # print(f"Alert, variable {vars_to_check[vc]} is unchecked in function {all_funcs[j][1]} in contract {all_funcs[j][0]}")
                            alerts.append({
                                'code':5, 
                                'message': f"Alert, variable '{vars_to_check[vc]}' is unchecked in function '{all_funcs[j][1]}' in contract '{all_funcs[j][0]}'"
                            })
                    # print("----------")
    return alerts

##############################################################

### Task 6- try catch

def extract_asserts(bodies):
    ret = []
    for i in range(len(bodies)):
        var_inds = [m.start() for m in re.finditer('assert', bodies[i])]
        ret_temp = []
        for k in range(len(var_inds)):
            eol = None
            par_iter = 0
            par_ind = bodies[i][var_inds[k]:].index('(')
            for j in range(var_inds[k]+par_ind+1,len(bodies[i])):                    
                if bodies[i][j] == ")":
                    par_iter -= 1
                if bodies[i][j] == "(":
                    par_iter += 1
                if par_iter == -1:
                    eol = j
                    break
            if bodies[i][eol+1] == ';':
                eol += 1
            temp = bodies[i][var_inds[k]:eol+1]
            # temp = temp.replace('require','').strip()
            ret_temp.append(temp)
        ret.append(ret_temp)
    # print("ret     ", ret)
    return ret

def exceptions():
    alerts = []
    all_funcs = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("conditionals   ", func_conditionals)
        dvars = deepcopy(funcs)
        x = [i.insert(0,contract_name) for i in dvars]
        # print("dvars    ", dvars)
        all_funcs.extend(dvars)
    # print("all funcs   ", all_funcs[0])
    ######
    for i in range(len(all_funcs)):
        f_body = all_funcs[i][4]
        var_inds = [m.start() for m in re.finditer('try', f_body)]
        # print("var inds    ", var_inds)
        try_catches = []
        for k in range(len(var_inds)):
            temp = []
            for j in range(len(f_body)):
                eol = None
                par_iter = 0
                par_ind = f_body[var_inds[k]:].index('{')
                for j in range(var_inds[k]+par_ind+1,len(f_body)):
                    if f_body[j] == "}":
                        par_iter -= 1
                    if f_body[j] == "{":
                        par_iter += 1
                    if par_iter == -1:
                        eol = j
                        break
            # print("try phrase   ", f_body[var_inds[k]:eol+1])
            temp.append(f_body[var_inds[k]:eol+1])
            # print("rest    ", f_body[eol+1:])
            rest = f_body[eol+1:].strip()
            if rest[:len('catch')] == 'catch':
                for j in range(len(rest)):
                    eol2 = None
                    par_iter = 0
                    par_ind = rest.index('{')
                    for j in range(par_ind+1,len(rest)):
                        if rest[j] == "}":
                            par_iter -= 1
                        if rest[j] == "{":
                            par_iter += 1
                        if par_iter == -1:
                            eol2 = j
                            break
                # print("catch phrase    ", rest[:eol2+1])
                temp.append(rest[:eol2+1])
            try_catches.append(temp)
        # print("try catches   ", try_catches)
        #####
        #####
        for j in range(len(try_catches)):
            if len(try_catches[j]) == 1:
                # print("--------------")
                # print(f"Alert: Unhandled exception in line: {try_catches[j][0]}")
                # print("--------------")
                pass
            elif len(try_catches[j]) == 2:
                if "revert" in try_catches[j][1]:
                    # print("--------------")
                    # print(f"Alert: Revert action found in line: {try_catches[j][1]}")
                    # print("--------------")
                    alerts.append({
                        'code':6, 
                        'message': f"Alert: Revert action found in line: {try_catches[j][1]}"
                    })
                
                ####
                asserts = extract_asserts([try_catches[j][1]])[0]
                if len(asserts) > 0:
                    # print("asserts    ", asserts)
                    alerts.append({
                        'code':6, 
                        'message': f"Alert: asserts:  {asserts}"
                    })
    return alerts
                    
########################################################
## Task 7

def find_uniques(inp):
    unique = []
    for i in inp:
        if not i in unique:
            unique.append(i)
    return unique

def complicated_calculations():
    alerts = []
    all_vars = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("vars   ", vars)
        dvars = deepcopy(vars)
        x = [i.insert(0,contract_name) for i in dvars]
        # print("dvars    ", dvars)
        all_vars.extend(dvars)
        ####
        # print("funcs    ", funcs)
        if len(funcs) > 0:
            dfuncs = []
            for j in deepcopy(funcs):
                # print("j[1]   ", j[1])
                if j[1] != [['']]:
                    # print("------")
                    x = [i.insert(0,contract_name) for i in j[1]]
                    dfuncs.extend(j[1])
            # x = [i.insert(0,contract_name) for i in dfuncs]
            # print("dfuncs    ", dfuncs)
            all_vars.extend(dfuncs)

    # print("vars    ", all_vars)
    # all_vars = list(np.unique(all_vars))
    # all_vars = list(set(all_vars))
    all_vars = find_uniques(all_vars)
    # unallowed_vars = ['supply', 'value']
    unallowed_vars = []
    for idx, una_var in enumerate(unallowed_vars):
        print(" ------------------------------------------      ", una_var)
        current_var_name = ''
        var_default_name = una_var #'totalSupply'
        var_names = [i[-1] for i in all_vars]
        # print("var names    ", var_names)
        corresponding_contract = None
        if var_default_name in var_names:
            if var_names.count(var_default_name) > 1:
                # print("    ---  warning  ---    ")
                # print("multiple definitions of total supply")
                ind = var_names.index(var_default_name)
                corresponding_contract = all_vars[ind][0]
                # current_var_name = 'totalSupply'
                current_var_name = var_names[ind]
            else:
                ind = var_names.index(var_default_name)
                # print("ind    ", ind)
                corresponding_contract = all_vars[ind][0]
                # print("corresponding contract    ", corresponding_contract)
                # current_var_name = 'totalSupply'
                current_var_name = var_names[ind]
        else:
            sim = similar_string(una_var, var_names)
            if sim is None:
                # print(f"No similar variable was found for {una_var}")
                continue
            else:
                current_var_name = sim
                ind = var_names.index(current_var_name)
                corresponding_contract = all_vars[ind][0]
        ####
        if corresponding_contract is not None:
            susceptible_vars = [current_var_name]
            funcs = reader.contracts_mem[corresponding_contract]['funcs']
            bodies = [i[-1] for i in funcs]
            # print("bodies    ", bodies)
            for sus in susceptible_vars:
                for bb in range(len(bodies)):
                    # print("body     ", bodies[bb])
                    # t = tot_sup_name
                    t = sus
                    var_inds = [m.start() for m in re.finditer(t, bodies[bb])]
                    # print("var inds    ", var_inds)
                    for i in range(len(var_inds)):
                        bol = None
                        for j in range(var_inds[i],0,-1):
                            if bodies[bb][j] == ";":
                                bol = j+1
                                break
                        if bol is None:
                            bol = 1
                        #######
                        eol = None
                        for j in range(var_inds[i],len(bodies[bb])):
                            if bodies[bb][j] == ";":
                                eol = j
                                break
                        # print("eol    ", eol)
                        if eol is None:
                            eol = len(bodies[bb])-1
                        # print("beol     ", bol, " -  ", eol)
                        # temp = bodies[bb][var_inds[i]:eol+1]
                        temp = bodies[bb][bol:eol+1]
                        # print("temp    ", temp)
                        temp = temp.replace(reader.line_sep,'').strip()
                        #############
                        if '.mul' in temp and '.div' in temp:
                            # print("--------")
                            # print(f"Alert: Multiplication and division occured simultaneously")
                            # print("Line:    ", temp)
                            # print("--------")
                            alerts.append({
                                'code':7, 
                                'message': f"Alert: Multiplication and division occured simultaneously in line: {temp}"
                            })
                        if '.div' in temp:
                            # print("--------")
                            # print(f"Alert: Division is occured")
                            # print("Line:    ", temp)
                            # print("--------")
                            alerts.append({
                                'code':7, 
                                'message': f"Alert: Division is occured in line: {temp}"
                            })
    if len(unallowed_vars) == 0:
        for k,v in reader.contracts_mem.items():
            # funcs = reader.contracts_mem[corresponding_contract]['funcs']
            funcs = v['funcs']
            bodies = [i[-1] for i in funcs]
            # print("bodies    ", bodies)
            for bb in range(len(bodies)):
                # print("body     ", bodies[bb])
                # t = tot_sup_name
                lines = bodies[bb].split(";")
                for temp in lines:
                    #############
                    if '.mul' in temp and '.div' in temp:
                        # print("--------")
                        # print(f"Alert: Multiplication and division occured simultaneously")
                        # print("Line:    ", temp)
                        # print("--------")
                        alerts.append({
                            'code':7, 
                            'message': f"Alert: Multiplication and division occured simultaneously in line: {temp}"
                        })
                    ###
                    if 'math.' in temp:
                        # print("--------")
                        # print(f"Alert: Math functions are used")
                        # print("Line:    ", temp)
                        # print("--------")
                        alerts.append({
                            'code':7, 
                            'message': f"Alert: Math functions are used in line: {temp}"
                        })
                    ###
                    brack_iter = 0
                    start_flag = 0
                    e_ind = None
                    if '(' in temp:
                        s_ind = temp.index('(')
                        for i in range(s_ind, len(temp)):
                            if temp[i] == "(":
                                brack_iter += 1
                                start_flag = 1
                                if brack_iter >= 2 and (('.mul' in temp) or ('.div' in temp) or ('.sub' in temp) or ('.add' in temp)):
                                    # print("--------")
                                    # print(f"Alert: complicated parenthesis are used")
                                    # print("Line:    ", temp)
                                    # print("--------")
                                    alerts.append({
                                        'code':7, 
                                        'message': f"Alert: Complicated parenthesis are used in line: {temp}"
                                    })
                                    break
                                continue
                            if temp[i] == ")":
                                brack_iter -= 1
    return alerts

#############################################################
# ## Task 8
def check_order():
    alerts = []
    all_funcs = []
    all_conditionals = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("conditionals   ", func_conditionals)
        dvars = deepcopy(funcs)
        x = [i.insert(0,contract_name) for i in dvars]
        # print("dvars    ", dvars)
        all_funcs.extend(dvars)
        all_conditionals.extend(func_conditionals)
    ################
    fetch_names = ['rebase']
    transfer_names = ['transfer', 'withdraw', 'unstake']
    fh_funcs = []
    for idx, var in enumerate(fetch_names):
        for i in range(len(all_funcs)):
            if var in all_funcs[i][1]:
                fh_funcs.append(all_funcs[i][1])
    fh_funcs = list(set(fh_funcs))
    
    tf_funcs = []
    for idx, var in enumerate(transfer_names):
        for i in range(len(all_funcs)):
            if var in all_funcs[i][1]:
                tf_funcs.append(all_funcs[i][1])
    tf_funcs = list(set(tf_funcs))

    # print("fetch func names   ", fh_funcs)
    # print("transfer func names   ", tf_funcs)
    ####
    ## find transfer occurence
    for idx, var in enumerate(tf_funcs):
        for i in range(len(all_funcs)):
            f_body = all_funcs[i][4]
            # print(" fbody    ", f_body)
            if var in f_body:
                var_inds = [m.start() for m in re.finditer(var, f_body)]
                # print("var inds   ", var_inds)
                line_indics = []
                for k, vind in enumerate(var_inds):
                    # print("k   ", k)
                    bol = None
                    for j in range(vind,0,-1):
                        if f_body[j] == ";":
                            bol = j+1
                            break
                    if bol is None:
                        bol = 1
                    #######
                    eol = None
                    for j in range(vind,len(f_body)):
                        if f_body[j] == ";":
                            eol = j
                            break
                    # print("eol    ", eol)
                    if eol is None:
                        eol = len(f_body)-1
                    temp = f_body[bol:eol+1]
                    line_indics.append([bol,eol])
                    if 'require' in temp:
                        continue
                    # print("temp    ", temp)
                    temp = temp.replace(reader.line_sep,'').strip()
                    ##############
                    if k == 0:
                        used_flag = False
                        for fh in fh_funcs:
                            if fh in [f_body[:bol]]:
                                used_flag = True
                        if not used_flag:
                            # print(f"Alert1: fetch function did not occur before transfer in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract")
                            alerts.append({
                                'code':8, 
                                'message': f"Alert1: fetch function did not occur before transfer in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract"
                            })
                    else:
                        used_flag = False
                        for fh in fh_funcs:
                            prev_eol = line_indics[-2][1]
                            if fh in [f_body[prev_eol:bol]]:
                                used_flag = True
                        if not used_flag:
                            # print(f"Alert2: fetch function did not occur before transfer in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract")
                            alerts.append({
                                'code':8, 
                                'message': f"Alert2: fetch function did not occur before transfer in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract"
                            })
    ## find fetch occurence
    for idx, var in enumerate(fh_funcs):
        for i in range(len(all_funcs)):
            f_body = all_funcs[i][4]
            if var in f_body:
                var_inds = [m.start() for m in re.finditer(var, f_body)]
                # line_indics = []
                for k, vind in enumerate(var_inds):
                    # print("k   ", k)
                    bol = None
                    for j in range(vind,0,-1):
                        if f_body[j] == ";":
                            bol = j+1
                            break
                    if bol is None:
                        bol = 1
                    #######
                    eol = None
                    eol2 = None
                    for j in range(vind,len(f_body)):
                        if f_body[j] == ";":
                            eol = j
                            break
                    # print("eol    ", eol)
                    if eol is None:
                        eol = len(f_body)-1
                    else:
                        for j in range(eol,len(f_body)):
                            if f_body[j] == ";":
                                eol2 = j
                                break
                    if eol2 is None:
                        eol2 = len(f_body)-1
                    temp = f_body[bol:eol+1]
                    # line_indics.append([bol,eol])
                    if 'require' in temp:
                        continue
                    # print("temp    ", temp)
                    temp = temp.replace(reader.line_sep,'').strip()
                    ##############
                    used_flag = False
                    for fh in tf_funcs:
                        if fh in [f_body[eol:]]:
                            used_flag = True
                    if not used_flag:
                        # print(f"Alert3: transfer function did not occur after fetch in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract")
                        alerts.append({
                            'code':8, 
                            'message': f"Alert3: transfer function did not occur after fetch in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract"
                        })
                    ##############
                    used_flag = False
                    for fh in tf_funcs:
                        # if fh in [f_body[eol:eol2+1]]:
                        if fh in [f_body[:eol2+1]]:
                            used_flag = True
                    if not used_flag:
                        # print(f"Alert4: transfer function did not occur extactly in next line of fetch in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract")
                        alerts.append({
                            'code':8, 
                            'message': f"Alert4: transfer function did not occur in next line of fetch in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract"
                        })
    return alerts

##################################################################                   
## Task 9
def withdraw_check():
    alerts = []
    all_funcs = []
    all_conditionals = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("conditionals   ", func_conditionals)
        dvars = deepcopy(funcs)
        x = [i.insert(0,contract_name) for i in dvars]
        # print("dvars    ", dvars)
        all_funcs.extend(dvars)
        all_conditionals.extend(func_conditionals)
    ####
    withdraw_names = ["withdraw","unstake","transfer"]
    systematic_functions = ['Transfer', 'Approval', 'revert','s_feeManager','verify']
    # withdraw_names.extend(systematic_functions)
    wh_funcs = []
    for idx, var in enumerate(withdraw_names):
        for i in range(len(all_funcs)):
            if var in all_funcs[i][1]:
                wh_funcs.append(all_funcs[i][1])
    wh_funcs = list(set(wh_funcs))
    # print("wh funcs    ", wh_funcs)
    for idx, var in enumerate(wh_funcs):
        # print(" ***  var   ", var)
        for i in range(len(all_funcs)):
            f_body = all_funcs[i][4]
            if var+'(' in f_body:
                var_inds = [m.start() for m in re.finditer(var, f_body)]
                line_indics = []
                for k, vind in enumerate(var_inds):
                    # print("k   ", k)
                    bol = None
                    for j in range(vind,0,-1):
                        if f_body[j] == ";":
                            bol = j+1
                            break
                    if bol is None:
                        bol = 1
                    #######
                    eol = None
                    for j in range(vind,len(f_body)):
                        if f_body[j] == ";":
                            eol = j
                            break
                    # print("eol    ", eol)
                    if eol is None:
                        eol = len(f_body)-1
                    temp = f_body[bol:eol+1]
                    line_indics.append([bol,eol])
                    if 'require' in temp:
                        continue
                    # print("line of called function:    ", temp)
                    temp = temp.replace(reader.line_sep,'').strip()
                    ##############
                    if k == 0:
                        reqs = extract_requirements([f_body[:bol]])[0]
                        if len(reqs) > 0:
                            # print("reqs    ", reqs)
                            alerts.append({
                                'code':9, 
                                'message': f"Alert: requirements: {reqs}"
                            })
                        conditionals = reader.extract_func_conditionals([f_body[:bol]])[0]
                        if len(conditionals) > 0:
                            # print("conditionals    ", conditionals)
                            alerts.append({
                                'code':9, 
                                'message': f"Alert: conditionals: {conditionals}"
                            })
                        exp = extract_exceptions(f_body[:bol])
                        if len(exp) > 0:
                            # print("exceptions    ", exp)
                            alerts.append({
                                'code':9, 
                                'message': f"Alert: Exceptions: {exp}"
                            })
                        ##
                        for sfind, sf in enumerate(systematic_functions):
                            if sf in f_body[:bol]:
                                # print(f"Function {sf} is before current line.")
                                alerts.append({
                                    'code':9, 
                                    'message': f"Function {sf} is before current line."
                                })
                        # print("------------------")
                    else:
                        # print("line indics   ", line_indics)
                        prev_eol = line_indics[-2][1]
                        reqs = extract_requirements([f_body[prev_eol:bol]])[0]
                        if len(reqs) > 0:
                            # print("reqs    ", reqs)
                            alerts.append({
                                'code':9, 
                                'message': f"Alert: requirements: {reqs}"
                            })
                        conditionals = reader.extract_func_conditionals([f_body[prev_eol:bol]])[0]
                        if len(conditionals) > 0:
                            # print("conditionals    ", conditionals)
                            alerts.append({
                                'code':9, 
                                'message': f"Alert: conditionals: {conditionals}"
                            })
                        exp = extract_exceptions(f_body[prev_eol:bol])
                        if len(exp) > 0:
                            # print("exceptions    ", exp)
                            alerts.append({
                                'code':9, 
                                'message': f"Alert: Exceptions: {exp}"
                            })
                        ##
                        for sfind, sf in enumerate(systematic_functions):
                            if sf in f_body[prev_eol:bol]:
                                # print(f"Function {sf} is before current line.")
                                alerts.append({
                                    'code':9, 
                                    'message': f"Function {sf} is before current line."
                                })
                        # print("------------------")
    return alerts

###############################################################
## Task 11
def similar_names():
    alerts = []
    for i in range(len(rets)):
        all_funcs = []
        all_vars = []
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dfuncs = deepcopy(funcs)
        x = [i.insert(0,contract_name) for i in dfuncs]
        all_funcs.extend(dfuncs)
        ####
        dvars = deepcopy(vars)
        x = [i.insert(0,contract_name) for i in dvars]
        all_vars.extend(dvars)
        # print("all vars   ", all_vars)
        ###########
    
        for i, func1 in enumerate(all_funcs):
            # print("----")
            # print("func1    ", func1)
            # print("----")
            for j, func2 in enumerate(all_funcs[i+1:]):
                # print("----")
                # print("func2    ", func2)
                # print("----")
                name = func1[1]
                name2 = func2[1]
                ratio = difflib.SequenceMatcher(None, name, name2).ratio()
                if ratio > 0.9:
                    if (len(name) - len(name2))/max(len(name),len(name2)) < 0.2:
                        # print(f"Alert: similar function names, function '{name}' in contract '{func1[0]}' and function '{name2}' in contract '{func2[0]}'")
                        alerts.append({
                            'code':11, 
                            'message': f"Alert: similar function names, function '{name}' in contract '{func1[0]}' and function '{name2}' in contract '{func2[0]}'"
                        })
        ####
        for i, var1 in enumerate(all_vars):
            # print("----")
            # print("var1    ", var1)
            # print("----")
            for j, var2 in enumerate(all_vars[i+1:]):
                # print("----")
                # print("var2    ", var2)
                # print("----")
                name = var1[-1]
                name2 = var2[-1]
                ratio = difflib.SequenceMatcher(None, name, name2).ratio()
                if ratio > 0.9:
                    if (len(name) - len(name2))/max(len(name),len(name2)) < 0.2:
                        # print(f"Alert: similar variable names, variable '{name}' in contract '{var1[0]}' and variable '{name2}' in contract '{var2[0]}'")
                        alerts.append({
                            'code':11, 
                            'message': f"Alert: similar variable names, variable '{name}' in contract '{func1[0]}' and variable '{name2}' in contract '{func2[0]}'"
                        })
    return alerts

###############################################
## task 12, outer calls

def intra_conytract_connection(high_connections, func_name):
    ret = False
    for i in high_connections:
        maps = i['func_func_mapping']
        for k,v in maps.items():
            # print("k   ", k)
            # print("v    ", v)
            if func_name in v:
                ret = True
    return ret

def outer_calls():
    alerts = []
    all_maps = {}
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        # print("contract name    ", contract_name)
        # print("ffmapping   ", func_func_mapping)
        all_maps[contract_name] = func_func_mapping
    # print("maps    ", all_maps)
    # print("high conn    ", high_connections)
    ###
    for k,v in all_maps.items():
        for kk,vv in v.items():
            if len(vv) == 0: #if function is not called by any other function
                funcs = reader.contracts_mem[k]['funcs']
                func_names = [i[0] for i in funcs]
                if kk in func_names:
                    ############################ if func is called in high connections
                    if intra_conytract_connection(high_connections, kk):
                        # print(f"function '{kk}' is used in high connections")
                        continue
                    ############################
                    # print("---------------------------------------------")
                    # print("func name    ", kk)
                    func_ind = func_names.index(kk)
                    func = funcs[func_ind]
                    # print("func   ", func)
                    # print("o    ", func[2])
                    if 'external' in func[2]: # function is external
                        # print("external")
                        only_flag = False
                        for j in func[2]: # check only flag
                            if 'only' in j:
                                only_flag = True
                        # print("only flag    ", only_flag)
                        if not only_flag:
                            # print(" * suspicious    ")
                            input_params = func[1]
                            if input_params == [['']]:
                                continue
                            # print("input params   ", input_params)
                            for var in input_params:
                                if var[-1] in func[3]:
                                    var_inds = [m.start() for m in re.finditer(var[-1], func[3])]
                                    for i in range(len(var_inds)):
                                        bol = None
                                        for j in range(var_inds[i],0,-1):
                                            if func[3][j] == ";":
                                                bol = j+1
                                                break
                                        if bol is None:
                                            bol = 1
                                        #######
                                        eol = None
                                        for j in range(var_inds[i],len(func[3])):
                                            if func[3][j] == ";":
                                                eol = j
                                                break
                                        # print("eol    ", eol)
                                        if eol is None:
                                            eol = len(func[3])-1
                                        # print("beol     ", bol, " -  ", eol)
                                        # temp = bodies[bb][var_inds[i]:eol+1]
                                        temp = func[3][bol:eol+1]
                                        # print("temp    ", temp)
                                        temp = temp.replace(reader.line_sep,'').strip()
                                        # print("temp    ", temp)
                                        if ('return' in temp) or ('if' in temp) or ('require' in temp)or ('emit' in temp):
                                            continue
                                        # print("--------")
                                        # print(f"Alert: Outer manipulation")
                                        # print("func name    ", kk)
                                        # print("Line:    ", temp)
                                        # print("--------")
                                        alerts.append({
                                            'code':12, 
                                            'message': f"Outer manipulation in function {kk}, line: {temp}"
                                        })
    return alerts

###############################################
## graphical demonstration
#################    oke



cluster_border_color = "#4D869C"
cluster_background_color = "#F8F6F422"
# var_fill_color = "#D2E9E9"
var_fill_color = "#95D2B380"
# func_fill_color = "#ffffff"
# func_fill_color = "#95D2B380"
func_fill_color = "#D2E9E9"
sysfunc_fill_color = "#E3F4F4"


edge_color = "#D77FA1"

def plot_graph(rets):
    print("--------------------------------------------------------------------------")
    print("Generating plot ... ")
    
    dot = graphviz.Digraph('round-table',format='png',graph_attr={'label': filename,'splines': 'ortho','nodesep': '1.2'})

    ff_edges = []
    vf_edges = []

    ## plot each contract in a seperated box
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
    
        sys_funcs = [k for k,v in sysfunc_func_mapping.items() if len(v) > 0]

        # print("--------------------------------------------------------------------------")
        # print("contract name    ", contract_name)
        # print("sys funcs   ", sys_funcs)
        # print("func names    ", [i[0] for i in funcs])

        dot.attr(rankdir='LR')
        with dot.subgraph(name="cluster_{}".format(i)) as B:
            B.attr(label=contract_name, color=cluster_border_color, penwidth='2', bgcolor=cluster_background_color, fontcolor=cluster_border_color, fontsize='26pt')
            with B.subgraph() as s:
                s.attr('node', shape='ellipse', style="filled")
                # plot variables
                for i in range(len(vars)):
                    s.node('var_{}_{}'.format(contract_name,vars[i][-1]),vars[i][-1], fillcolor=var_fill_color, color=var_fill_color)
                # plot structs
                for i in range(len(structs)):
                    s.node('var_{}_{}'.format(contract_name,structs[i][0]),structs[i][0], fillcolor=var_fill_color, color=var_fill_color)
                #########
                s.attr('node', shape='cylinder')
                # plot objects
                for i in range(len(objs)):
                    s.node('obj_{}_{}'.format(contract_name,objs[i][-1]),"{}\nContract: {}".format(objs[i][-1], objs[i][0]), fillcolor=var_fill_color, color=var_fill_color)
                #########
                s.attr('node', shape='rectangle')
                # plot functions
                for i in range(len(funcs)):
                    s.node('func_{}_{}'.format(contract_name, funcs[i][0]),"{}\nInputs: {}\nConditionals:  {}".format(funcs[i][0],funcs[i][1],func_conditionals[i]), fillcolor=func_fill_color, color=func_fill_color)
                # plot events
                for i in range(len(events)):
                    s.node('func_{}_{}'.format(contract_name, events[i][0]),"{}\nInputs: {}".format(events[i][0],events[i][1]), fillcolor=func_fill_color, color=func_fill_color)
                #########
                s.attr('node', shape='parallelogram')
                # plot system functions
                for i in range(len(sys_funcs)):
                    s.node('sysfunc_{}_{}'.format(contract_name, sys_funcs[i]), sys_funcs[i], fillcolor=sysfunc_fill_color, color=sysfunc_fill_color)
                ##########
                # plot variable-function mapping
                for k,v in var_func_mapping.items():
                    for i in range(len(v)):
                        s.edge('var_{}_{}'.format(contract_name, k), 'func_{}_{}'.format(contract_name, v[i]), color=edge_color)
                ##########
                # plot function-function mapping
                for k,v in func_func_mapping.items():
                    for i in range(len(v)):
                        if 'super' in v[i]:
                            t = v[i].replace('super.','')
                        else:
                            t = v[i].replace('super.','')
                            s.edge('func_{}_{}'.format(contract_name, k), 'func_{}_{}'.format(contract_name, t), color=edge_color)
                ###########
                # plot system_function-function mapping
                for k,v in sysfunc_func_mapping.items():
                    for i in range(len(v)):
                        t = v[i]
                        s.edge('func_{}_{}'.format(contract_name, t), 'sysfunc_{}_{}'.format(contract_name, k), color=edge_color)
                ###########
                # plot object-function mapping
                for k,v in obj_func_mapping.items():
                    for i in range(len(v)):
                        t = v[i][0]
                        label = v[i][1]
                        s.edge('func_{}_{}'.format(contract_name, t), 'obj_{}_{}'.format(contract_name, k), xlabel=label, fontsize="10pt", margin="1", pad="1", color=edge_color)
                
            
    #### plot connections between multiple contracts
    for m in range(len(high_connections)):
        conn = high_connections[m]
        par = conn['parent']
        chl = conn['child']
        vf_map = conn['var_func_mapping']
        ff_map = conn['func_func_mapping']
        # print("vf mapping    ", vf_map)
        for k,v in vf_map.items():
            for n in range(len(v)):
                dot.edge('var_{}_{}'.format(par, k), 'func_{}_{}'.format(chl, v[n]), color=edge_color)
        for k,v in ff_map.items():
            for n in range(len(v)):
                dot.edge('func_{}_{}'.format(par, k), 'func_{}_{}'.format(chl, v[n]), color=edge_color)

    ####
    dot.render(filename+'.gv',directory='',view=False)



# with open('./doctest-output/'+filename+'.gv') as f:
#     dot = f.read()
#     display(graphviz.Source(dot))


#############  run
if task == '1':
    alerts = contract_version()
    demonstrate_alerts(alerts)
elif task == '2':
    alerts = unallowed_manipulation()
    demonstrate_alerts(alerts)
elif task == '3':
    alerts = staking()
    demonstrate_alerts(alerts)
elif task == '4':
    alerts = pool_interactions()
    demonstrate_alerts(alerts)
elif task == '5':
    alerts = local_points()
    demonstrate_alerts(alerts)
elif task == '6':
    alerts = exceptions()
    demonstrate_alerts(alerts)
elif task == '7':
    alerts = complicated_calculations()
    demonstrate_alerts(alerts)
elif task == '8':
    alerts = check_order()
    demonstrate_alerts(alerts)
elif task == '9':
    alerts = withdraw_check()
    demonstrate_alerts(alerts)
elif task == '10':
    alerts = similar_names()
    # print(alerts)
    demonstrate_alerts(alerts)
elif task == '11':
    alerts = outer_calls()
    demonstrate_alerts(alerts)
elif task == '12':
    plot_graph(rets)
elif task == '13':
    alerts = contract_version()
    demonstrate_alerts(alerts)
    ##
    alerts = unallowed_manipulation()
    demonstrate_alerts(alerts)
    ##
    alerts = staking()
    demonstrate_alerts(alerts)
    ##
    alerts = pool_interactions()
    demonstrate_alerts(alerts)
    ##
    alerts = local_points()
    demonstrate_alerts(alerts)
    ##
    alerts = exceptions()
    demonstrate_alerts(alerts)
    ##
    alerts = complicated_calculations()
    demonstrate_alerts(alerts)
    ##
    alerts = check_order()
    demonstrate_alerts(alerts)
    ##
    alerts = withdraw_check()
    demonstrate_alerts(alerts)
    ##
    alerts = similar_names()
    # print(alerts)
    demonstrate_alerts(alerts)
    ##
    alerts = outer_calls()
    demonstrate_alerts(alerts)
    ##
    plot_graph(rets)
