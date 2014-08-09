import operator
import struct

import six
import jinja2
import py

from bpf import opcodes

bpf_python_code_template_file = py.path.local(__file__)\
                                       .dirpath()\
                                       .join("bpf_python_filter.tmpl")


bpf_python_code_template = jinja2.Template(bpf_python_code_template_file.read())



def compile_program(bpf_program):
    local_dict = {}
    code = get_python_code(bpf_program)
    print code
    six.exec_(code, {}, local_dict)
    return local_dict['bpf_filter']

def get_python_code(bpf_program):
    env = jinja2.Environment()
    return bpf_python_code_template.render(bpf_program=bpf_program,
                                           bitwiseor=lambda *args: reduce(operator.or_, args),
                                           SIZE_OF_INT32 = struct.calcsize("!L"),  # 4
                                           SIZE_OF_SHORT = struct.calcsize("!H"), # 2
                                           SIZE_OF_BYTE = struct.calcsize("!B"),  # 1
                                           **vars(opcodes))
