#
# QAPI helper library
#
# Copyright IBM, Corp. 2011
# Copyright (c) 2013-2015 Red Hat Inc.
#
# Authors:
#  Anthony Liguori <aliguori@us.ibm.com>
#  Markus Armbruster <armbru@redhat.com>
#
# This work is licensed under the terms of the GNU GPL, version 2.
# See the COPYING file in the top-level directory.

import re
from ordereddict import OrderedDict
import os
import sys

builtin_types = {
    'str':      'QTYPE_QSTRING',
    'int':      'QTYPE_QINT',
    'number':   'QTYPE_QFLOAT',
    'bool':     'QTYPE_QBOOL',
    'int8':     'QTYPE_QINT',
    'int16':    'QTYPE_QINT',
    'int32':    'QTYPE_QINT',
    'int64':    'QTYPE_QINT',
    'uint8':    'QTYPE_QINT',
    'uint16':   'QTYPE_QINT',
    'uint32':   'QTYPE_QINT',
    'uint64':   'QTYPE_QINT',
    'size':     'QTYPE_QINT',
}

# Whitelist of commands allowed to return a non-dictionary
returns_whitelist = [
    # From QMP:
    'human-monitor-command',
    'query-migrate-cache-size',
    'query-tpm-models',
    'query-tpm-types',
    'ringbuf-read',

    # From QGA:
    'guest-file-open',
    'guest-fsfreeze-freeze',
    'guest-fsfreeze-freeze-list',
    'guest-fsfreeze-status',
    'guest-fsfreeze-thaw',
    'guest-get-time',
    'guest-set-vcpus',
    'guest-sync',
    'guest-sync-delimited',

    # From qapi-schema-test:
    'user_def_cmd3',
]

enum_types = []
struct_types = []
union_types = []
events = []
all_names = {}

def error_path(parent):
    res = ""
    while parent:
        res = ("In file included from %s:%d:\n" % (parent['file'],
                                                   parent['line'])) + res
        parent = parent['parent']
    return res

class QAPISchemaError(Exception):
    def __init__(self, schema, msg):
        self.input_file = schema.input_file
        self.msg = msg
        self.col = 1
        self.line = schema.line
        for ch in schema.src[schema.line_pos:schema.pos]:
            if ch == '\t':
                self.col = (self.col + 7) % 8 + 1
            else:
                self.col += 1
        self.info = schema.parent_info

    def __str__(self):
        return error_path(self.info) + \
            "%s:%d:%d: %s" % (self.input_file, self.line, self.col, self.msg)

class QAPIExprError(Exception):
    def __init__(self, expr_info, msg):
        self.info = expr_info
        self.msg = msg

    def __str__(self):
        return error_path(self.info['parent']) + \
            "%s:%d: %s" % (self.info['file'], self.info['line'], self.msg)

class QAPISchema:

    def __init__(self, fp, input_relname=None, include_hist=[],
                 previously_included=[], parent_info=None):
        """ include_hist is a stack used to detect inclusion cycles
            previously_included is a global state used to avoid multiple
                                inclusions of the same file"""
        input_fname = os.path.abspath(fp.name)
        if input_relname is None:
            input_relname = fp.name
        self.input_dir = os.path.dirname(input_fname)
        self.input_file = input_relname
        self.include_hist = include_hist + [(input_relname, input_fname)]
        previously_included.append(input_fname)
        self.parent_info = parent_info
        self.src = fp.read()
        if self.src == '' or self.src[-1] != '\n':
            self.src += '\n'
        self.cursor = 0
        self.line = 1
        self.line_pos = 0
        self.exprs = []
        self.accept()

        while self.tok != None:
            expr_info = {'file': input_relname, 'line': self.line, 'parent': self.parent_info}
            expr = self.get_expr(False)
            if isinstance(expr, dict) and "include" in expr:
                if len(expr) != 1:
                    raise QAPIExprError(expr_info, "Invalid 'include' directive")
                include = expr["include"]
                if not isinstance(include, str):
                    raise QAPIExprError(expr_info,
                                        'Expected a file name (string), got: %s'
                                        % include)
                include_path = os.path.join(self.input_dir, include)
                for elem in self.include_hist:
                    if include_path == elem[1]:
                        raise QAPIExprError(expr_info, "Inclusion loop for %s"
                                            % include)
                # skip multiple include of the same file
                if include_path in previously_included:
                    continue
                try:
                    fobj = open(include_path, 'r')
                except IOError, e:
                    raise QAPIExprError(expr_info,
                                        '%s: %s' % (e.strerror, include))
                exprs_include = QAPISchema(fobj, include, self.include_hist,
                                           previously_included, expr_info)
                self.exprs.extend(exprs_include.exprs)
            else:
                expr_elem = {'expr': expr,
                             'info': expr_info}
                self.exprs.append(expr_elem)

    def accept(self):
        while True:
            self.tok = self.src[self.cursor]
            self.pos = self.cursor
            self.cursor += 1
            self.val = None

            if self.tok == '#':
                self.cursor = self.src.find('\n', self.cursor)
            elif self.tok in ['{', '}', ':', ',', '[', ']']:
                return
            elif self.tok == "'":
                string = ''
                esc = False
                while True:
                    ch = self.src[self.cursor]
                    self.cursor += 1
                    if ch == '\n':
                        raise QAPISchemaError(self,
                                              'Missing terminating "\'"')
                    if esc:
                        string += ch
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == "'":
                        self.val = string
                        return
                    else:
                        string += ch
            elif self.tok in "tfn":
                val = self.src[self.cursor - 1:]
                if val.startswith("true"):
                    self.val = True
                    self.cursor += 3
                    return
                elif val.startswith("false"):
                    self.val = False
                    self.cursor += 4
                    return
                elif val.startswith("null"):
                    self.val = None
                    self.cursor += 3
                    return
            elif self.tok == '\n':
                if self.cursor == len(self.src):
                    self.tok = None
                    return
                self.line += 1
                self.line_pos = self.cursor
            elif not self.tok.isspace():
                raise QAPISchemaError(self, 'Stray "%s"' % self.tok)

    def get_members(self):
        expr = OrderedDict()
        if self.tok == '}':
            self.accept()
            return expr
        if self.tok != "'":
            raise QAPISchemaError(self, 'Expected string or "}"')
        while True:
            key = self.val
            self.accept()
            if self.tok != ':':
                raise QAPISchemaError(self, 'Expected ":"')
            self.accept()
            if key in expr:
                raise QAPISchemaError(self, 'Duplicate key "%s"' % key)
            expr[key] = self.get_expr(True)
            if self.tok == '}':
                self.accept()
                return expr
            if self.tok != ',':
                raise QAPISchemaError(self, 'Expected "," or "}"')
            self.accept()
            if self.tok != "'":
                raise QAPISchemaError(self, 'Expected string')

    def get_values(self):
        expr = []
        if self.tok == ']':
            self.accept()
            return expr
        if not self.tok in "{['tfn":
            raise QAPISchemaError(self, 'Expected "{", "[", "]", string, '
                                  'boolean or "null"')
        while True:
            expr.append(self.get_expr(True))
            if self.tok == ']':
                self.accept()
                return expr
            if self.tok != ',':
                raise QAPISchemaError(self, 'Expected "," or "]"')
            self.accept()

    def get_expr(self, nested):
        if self.tok != '{' and not nested:
            raise QAPISchemaError(self, 'Expected "{"')
        if self.tok == '{':
            self.accept()
            expr = self.get_members()
        elif self.tok == '[':
            self.accept()
            expr = self.get_values()
        elif self.tok in "'tfn":
            expr = self.val
            self.accept()
        else:
            raise QAPISchemaError(self, 'Expected "{", "[" or string')
        return expr

def find_base_fields(base):
    base_struct_define = find_struct(base)
    if not base_struct_define:
        return None
    return base_struct_define['data']

# Return the qtype of an alternate branch, or None on error.
def find_alternate_member_qtype(qapi_type):
    if builtin_types.has_key(qapi_type):
        return builtin_types[qapi_type]
    elif find_struct(qapi_type):
        return "QTYPE_QDICT"
    elif find_enum(qapi_type):
        return "QTYPE_QSTRING"
    elif find_union(qapi_type):
        return "QTYPE_QDICT"
    return None

# Return the discriminator enum define if discriminator is specified as an
# enum type, otherwise return None.
def discriminator_find_enum_define(expr):
    base = expr.get('base')
    discriminator = expr.get('discriminator')

    if not (discriminator and base):
        return None

    base_fields = find_base_fields(base)
    if not base_fields:
        return None

    discriminator_type = base_fields.get(discriminator)
    if not discriminator_type:
        return None

    return find_enum(discriminator_type)

valid_name = re.compile('^[a-zA-Z_][a-zA-Z0-9_.-]*$')
def check_name(expr_info, source, name, allow_optional = False,
               enum_member = False):
    global valid_name
    membername = name

    if not isinstance(name, str):
        raise QAPIExprError(expr_info,
                            "%s requires a string name" % source)
    if name.startswith('*'):
        membername = name[1:]
        if not allow_optional:
            raise QAPIExprError(expr_info,
                                "%s does not allow optional name '%s'"
                                % (source, name))
    # Enum members can start with a digit, because the generated C
    # code always prefixes it with the enum name
    if enum_member:
        membername = '_' + membername
    if not valid_name.match(membername):
        raise QAPIExprError(expr_info,
                            "%s uses invalid name '%s'" % (source, name))

def check_type(expr_info, source, value, allow_array = False,
               allow_dict = False, allow_optional = False, allow_metas = []):
    global all_names
    orig_value = value

    if value is None:
        return

    if value == '**':
        return

    # Check if array type for value is okay
    if isinstance(value, list):
        if not allow_array:
            raise QAPIExprError(expr_info,
                                "%s cannot be an array" % source)
        if len(value) != 1 or not isinstance(value[0], str):
            raise QAPIExprError(expr_info,
                                "%s: array type must contain single type name"
                                % source)
        value = value[0]
        orig_value = "array of %s" %value

    # Check if type name for value is okay
    if isinstance(value, str):
        if not value in all_names:
            raise QAPIExprError(expr_info,
                                "%s uses unknown type '%s'"
                                % (source, orig_value))
        if not all_names[value] in allow_metas:
            raise QAPIExprError(expr_info,
                                "%s cannot use %s type '%s'"
                                % (source, all_names[value], orig_value))
        return

    # value is a dictionary, check that each member is okay
    if not isinstance(value, OrderedDict):
        raise QAPIExprError(expr_info,
                            "%s should be a dictionary" % source)
    if not allow_dict:
        raise QAPIExprError(expr_info,
                            "%s should be a type name" % source)
    for (key, arg) in value.items():
        check_name(expr_info, "Member of %s" % source, key,
                   allow_optional=allow_optional)
        check_type(expr_info, "Member '%s' of %s" % (key, source), arg,
                   allow_array=True, allow_dict=True, allow_optional=True,
                   allow_metas=['built-in', 'union', 'alternate', 'struct',
                                'enum'])

def check_command(expr, expr_info):
    name = expr['command']
    check_type(expr_info, "'data' for command '%s'" % name,
               expr.get('data'), allow_dict=True, allow_optional=True,
               allow_metas=['union', 'struct'])
    returns_meta = ['union', 'struct']
    if name in returns_whitelist:
        returns_meta += ['built-in', 'alternate', 'enum']
    check_type(expr_info, "'returns' for command '%s'" % name,
               expr.get('returns'), allow_array=True, allow_dict=True,
               allow_optional=True, allow_metas=returns_meta)

def check_event(expr, expr_info):
    global events
    name = expr['event']
    params = expr.get('data')

    if name.upper() == 'MAX':
        raise QAPIExprError(expr_info, "Event name 'MAX' cannot be created")
    events.append(name)
    check_type(expr_info, "'data' for event '%s'" % name,
               expr.get('data'), allow_dict=True, allow_optional=True,
               allow_metas=['union', 'struct'])
    if params:
        for argname, argentry, optional, structured in parse_args(params):
            if structured:
                raise QAPIExprError(expr_info,
                                    "Nested structure define in event is not "
                                    "supported, event '%s', argname '%s'"
                                    % (expr['event'], argname))

def check_union(expr, expr_info):
    name = expr['union']
    base = expr.get('base')
    discriminator = expr.get('discriminator')
    members = expr['data']
    values = { 'MAX': '(automatic)' }

    # If the object has a member 'base', its value must name a complex type,
    # and there must be a discriminator.
    if base is not None:
        if discriminator is None:
            raise QAPIExprError(expr_info,
                                "Union '%s' requires a discriminator to go "
                                "along with base" %name)

    # Two types of unions, determined by discriminator.

    # With no discriminator it is a simple union.
    if discriminator is None:
        enum_define = None
        allow_metas=['built-in', 'union', 'alternate', 'struct', 'enum']
        if base is not None:
            raise QAPIExprError(expr_info,
                                "Simple union '%s' must not have a base"
                                % name)

    # Else, it's a flat union.
    else:
        # The object must have a string member 'base'.
        if not isinstance(base, str):
            raise QAPIExprError(expr_info,
                                "Flat union '%s' must have a string base field"
                                % name)
        base_fields = find_base_fields(base)
        if not base_fields:
            raise QAPIExprError(expr_info,
                                "Base '%s' is not a valid type"
                                % base)

        # The value of member 'discriminator' must name a non-optional
        # member of the base type.
        check_name(expr_info, "Discriminator of flat union '%s'" % name,
                   discriminator)
        discriminator_type = base_fields.get(discriminator)
        if not discriminator_type:
            raise QAPIExprError(expr_info,
                                "Discriminator '%s' is not a member of base "
                                "type '%s'"
                                % (discriminator, base))
        enum_define = find_enum(discriminator_type)
        allow_metas=['struct']
        # Do not allow string discriminator
        if not enum_define:
            raise QAPIExprError(expr_info,
                                "Discriminator '%s' must be of enumeration "
                                "type" % discriminator)

    # Check every branch
    for (key, value) in members.items():
        check_name(expr_info, "Member of union '%s'" % name, key)

        # Each value must name a known type; furthermore, in flat unions,
        # branches must be a struct
        check_type(expr_info, "Member '%s' of union '%s'" % (key, name),
                   value, allow_array=True, allow_metas=allow_metas)

        # If the discriminator names an enum type, then all members
        # of 'data' must also be members of the enum type.
        if enum_define:
            if not key in enum_define['enum_values']:
                raise QAPIExprError(expr_info,
                                    "Discriminator value '%s' is not found in "
                                    "enum '%s'" %
                                    (key, enum_define["enum_name"]))

        # Otherwise, check for conflicts in the generated enum
        else:
            c_key = _generate_enum_string(key)
            if c_key in values:
                raise QAPIExprError(expr_info,
                                    "Union '%s' member '%s' clashes with '%s'"
                                    % (name, key, values[c_key]))
            values[c_key] = key

def check_alternate(expr, expr_info):
    name = expr['alternate']
    members = expr['data']
    values = { 'MAX': '(automatic)' }
    types_seen = {}

    # Check every branch
    for (key, value) in members.items():
        check_name(expr_info, "Member of alternate '%s'" % name, key)

        # Check for conflicts in the generated enum
        c_key = _generate_enum_string(key)
        if c_key in values:
            raise QAPIExprError(expr_info,
                                "Alternate '%s' member '%s' clashes with '%s'"
                                % (name, key, values[c_key]))
        values[c_key] = key

        # Ensure alternates have no type conflicts.
        check_type(expr_info, "Member '%s' of alternate '%s'" % (key, name),
                   value,
                   allow_metas=['built-in', 'union', 'struct', 'enum'])
        qtype = find_alternate_member_qtype(value)
        assert qtype
        if qtype in types_seen:
            raise QAPIExprError(expr_info,
                                "Alternate '%s' member '%s' can't "
                                "be distinguished from member '%s'"
                                % (name, key, types_seen[qtype]))
        types_seen[qtype] = key

def check_enum(expr, expr_info):
    name = expr['enum']
    members = expr.get('data')
    values = { 'MAX': '(automatic)' }

    if not isinstance(members, list):
        raise QAPIExprError(expr_info,
                            "Enum '%s' requires an array for 'data'" % name)
    for member in members:
        check_name(expr_info, "Member of enum '%s'" %name, member,
                   enum_member=True)
        key = _generate_enum_string(member)
        if key in values:
            raise QAPIExprError(expr_info,
                                "Enum '%s' member '%s' clashes with '%s'"
                                % (name, member, values[key]))
        values[key] = member

def check_struct(expr, expr_info):
    name = expr['type']
    members = expr['data']

    check_type(expr_info, "'data' for type '%s'" % name, members,
               allow_dict=True, allow_optional=True)
    check_type(expr_info, "'base' for type '%s'" % name, expr.get('base'),
               allow_metas=['struct'])

def check_exprs(schema):
    for expr_elem in schema.exprs:
        expr = expr_elem['expr']
        info = expr_elem['info']

        if expr.has_key('enum'):
            check_enum(expr, info)
        elif expr.has_key('union'):
            check_union(expr, info)
        elif expr.has_key('alternate'):
            check_alternate(expr, info)
        elif expr.has_key('type'):
            check_struct(expr, info)
        elif expr.has_key('command'):
            check_command(expr, info)
        elif expr.has_key('event'):
            check_event(expr, info)
        else:
            assert False, 'unexpected meta type'

def check_keys(expr_elem, meta, required, optional=[]):
    expr = expr_elem['expr']
    info = expr_elem['info']
    name = expr[meta]
    if not isinstance(name, str):
        raise QAPIExprError(info,
                            "'%s' key must have a string value" % meta)
    required = required + [ meta ]
    for (key, value) in expr.items():
        if not key in required and not key in optional:
            raise QAPIExprError(info,
                                "Unknown key '%s' in %s '%s'"
                                % (key, meta, name))
    for key in required:
        if not expr.has_key(key):
            raise QAPIExprError(info,
                                "Key '%s' is missing from %s '%s'"
                                % (key, meta, name))


def parse_schema(input_file):
    global all_names
    exprs = []

    # First pass: read entire file into memory
    try:
        schema = QAPISchema(open(input_file, "r"))
    except (QAPISchemaError, QAPIExprError), e:
        print >>sys.stderr, e
        exit(1)

    try:
        # Next pass: learn the types and check for valid expression keys. At
        # this point, top-level 'include' has already been flattened.
        for builtin in builtin_types.keys():
            all_names[builtin] = 'built-in'
        for expr_elem in schema.exprs:
            expr = expr_elem['expr']
            info = expr_elem['info']
            if expr.has_key('enum'):
                check_keys(expr_elem, 'enum', ['data'])
                add_enum(expr['enum'], info, expr['data'])
            elif expr.has_key('union'):
                check_keys(expr_elem, 'union', ['data'],
                           ['base', 'discriminator'])
                add_union(expr, info)
            elif expr.has_key('alternate'):
                check_keys(expr_elem, 'alternate', ['data'])
                add_name(expr['alternate'], info, 'alternate')
            elif expr.has_key('type'):
                check_keys(expr_elem, 'type', ['data'], ['base'])
                add_struct(expr, info)
            elif expr.has_key('command'):
                check_keys(expr_elem, 'command', [],
                           ['data', 'returns', 'gen', 'success-response'])
                add_name(expr['command'], info, 'command')
            elif expr.has_key('event'):
                check_keys(expr_elem, 'event', [], ['data'])
                add_name(expr['event'], info, 'event')
            else:
                raise QAPIExprError(expr_elem['info'],
                                    "Expression is missing metatype")
            exprs.append(expr)

        # Try again for hidden UnionKind enum
        for expr_elem in schema.exprs:
            expr = expr_elem['expr']
            if expr.has_key('union'):
                if not discriminator_find_enum_define(expr):
                    add_enum('%sKind' % expr['union'], expr_elem['info'],
                             implicit=True)
            elif expr.has_key('alternate'):
                add_enum('%sKind' % expr['alternate'], expr_elem['info'],
                         implicit=True)

        # Final pass - validate that exprs make sense
        check_exprs(schema)
    except QAPIExprError, e:
        print >>sys.stderr, e
        exit(1)

    return exprs

def parse_args(typeinfo):
    if isinstance(typeinfo, str):
        struct = find_struct(typeinfo)
        assert struct != None
        typeinfo = struct['data']

    for member in typeinfo:
        argname = member
        argentry = typeinfo[member]
        optional = False
        structured = False
        if member.startswith('*'):
            argname = member[1:]
            optional = True
        if isinstance(argentry, OrderedDict):
            structured = True
        yield (argname, argentry, optional, structured)

def de_camel_case(name):
    new_name = ''
    for ch in name:
        if ch.isupper() and new_name:
            new_name += '_'
        if ch == '-':
            new_name += '_'
        else:
            new_name += ch.lower()
    return new_name

def camel_case(name):
    new_name = ''
    first = True
    for ch in name:
        if ch in ['_', '-']:
            first = True
        elif first:
            new_name += ch.upper()
            first = False
        else:
            new_name += ch.lower()
    return new_name

def c_var(name, protect=True):
    # ANSI X3J11/88-090, 3.1.1
    c89_words = set(['auto', 'break', 'case', 'char', 'const', 'continue',
                     'default', 'do', 'double', 'else', 'enum', 'extern', 'float',
                     'for', 'goto', 'if', 'int', 'long', 'register', 'return',
                     'short', 'signed', 'sizeof', 'static', 'struct', 'switch',
                     'typedef', 'union', 'unsigned', 'void', 'volatile', 'while'])
    # ISO/IEC 9899:1999, 6.4.1
    c99_words = set(['inline', 'restrict', '_Bool', '_Complex', '_Imaginary'])
    # ISO/IEC 9899:2011, 6.4.1
    c11_words = set(['_Alignas', '_Alignof', '_Atomic', '_Generic', '_Noreturn',
                     '_Static_assert', '_Thread_local'])
    # GCC http://gcc.gnu.org/onlinedocs/gcc-4.7.1/gcc/C-Extensions.html
    # excluding _.*
    gcc_words = set(['asm', 'typeof'])
    # C++ ISO/IEC 14882:2003 2.11
    cpp_words = set(['bool', 'catch', 'class', 'const_cast', 'delete',
                     'dynamic_cast', 'explicit', 'false', 'friend', 'mutable',
                     'namespace', 'new', 'operator', 'private', 'protected',
                     'public', 'reinterpret_cast', 'static_cast', 'template',
                     'this', 'throw', 'true', 'try', 'typeid', 'typename',
                     'using', 'virtual', 'wchar_t',
                     # alternative representations
                     'and', 'and_eq', 'bitand', 'bitor', 'compl', 'not',
                     'not_eq', 'or', 'or_eq', 'xor', 'xor_eq'])
    # namespace pollution:
    polluted_words = set(['unix', 'errno'])
    if protect and (name in c89_words | c99_words | c11_words | gcc_words | cpp_words | polluted_words):
        return "q_" + name
    return name.replace('-', '_').lstrip("*")

def c_fun(name, protect=True):
    return c_var(name, protect).replace('.', '_')

def c_list_type(name):
    return '%sList' % name

def type_name(name):
    if type(name) == list:
        return c_list_type(name[0])
    return name

def add_name(name, info, meta, implicit = False, source = None):
    global all_names
    if not source:
        source = "'%s'" % meta
    check_name(info, source, name)
    if name in all_names:
        raise QAPIExprError(info,
                            "%s '%s' is already defined"
                            % (all_names[name], name))
    if not implicit and name[-4:] == 'Kind':
        raise QAPIExprError(info,
                            "%s '%s' should not end in 'Kind'"
                            % (meta, name))
    all_names[name] = meta

def add_struct(definition, info):
    global struct_types
    name = definition['type']
    add_name(name, info, 'struct', source="'type'")
    struct_types.append(definition)

def find_struct(name):
    global struct_types
    for struct in struct_types:
        if struct['type'] == name:
            return struct
    return None

def add_union(definition, info):
    global union_types
    name = definition['union']
    add_name(name, info, 'union')
    union_types.append(definition)

def find_union(name):
    global union_types
    for union in union_types:
        if union['union'] == name:
            return union
    return None

def add_enum(name, info, enum_values = None, implicit = False):
    global enum_types
    add_name(name, info, 'enum', implicit)
    enum_types.append({"enum_name": name, "enum_values": enum_values})

def find_enum(name):
    global enum_types
    for enum in enum_types:
        if enum['enum_name'] == name:
            return enum
    return None

def is_enum(name):
    return find_enum(name) != None

eatspace = '\033EATSPACE.'

# A special suffix is added in c_type() for pointer types, and it's
# stripped in mcgen(). So please notice this when you check the return
# value of c_type() outside mcgen().
def c_type(name, is_param=False):
    if name == 'str':
        if is_param:
            return 'const char *' + eatspace
        return 'char *' + eatspace

    elif name == 'int':
        return 'int64_t'
    elif (name == 'int8' or name == 'int16' or name == 'int32' or
          name == 'int64' or name == 'uint8' or name == 'uint16' or
          name == 'uint32' or name == 'uint64'):
        return name + '_t'
    elif name == 'size':
        return 'uint64_t'
    elif name == 'bool':
        return 'bool'
    elif name == 'number':
        return 'double'
    elif type(name) == list:
        return '%s *%s' % (c_list_type(name[0]), eatspace)
    elif is_enum(name):
        return name
    elif name == None or len(name) == 0:
        return 'void'
    elif name in events:
        return '%sEvent *%s' % (camel_case(name), eatspace)
    else:
        return '%s *%s' % (name, eatspace)

def is_c_ptr(name):
    suffix = "*" + eatspace
    return c_type(name).endswith(suffix)

def genindent(count):
    ret = ""
    for i in range(count):
        ret += " "
    return ret

indent_level = 0

def push_indent(indent_amount=4):
    global indent_level
    indent_level += indent_amount

def pop_indent(indent_amount=4):
    global indent_level
    indent_level -= indent_amount

def cgen(code, **kwds):
    indent = genindent(indent_level)
    lines = code.split('\n')
    lines = map(lambda x: indent + x, lines)
    return '\n'.join(lines) % kwds + '\n'

def mcgen(code, **kwds):
    raw = cgen('\n'.join(code.split('\n')[1:-1]), **kwds)
    return re.sub(re.escape(eatspace) + ' *', '', raw)

def basename(filename):
    return filename.split("/")[-1]

def guardname(filename):
    guard = basename(filename).rsplit(".", 1)[0]
    for substr in [".", " ", "-"]:
        guard = guard.replace(substr, "_")
    return guard.upper() + '_H'

def guardstart(name):
    return mcgen('''

#ifndef %(name)s
#define %(name)s

''',
                 name=guardname(name))

def guardend(name):
    return mcgen('''

#endif /* %(name)s */

''',
                 name=guardname(name))

# ENUMName -> ENUM_NAME, EnumName1 -> ENUM_NAME1
# ENUM_NAME -> ENUM_NAME, ENUM_NAME1 -> ENUM_NAME1, ENUM_Name2 -> ENUM_NAME2
# ENUM24_Name -> ENUM24_NAME
def _generate_enum_string(value):
    c_fun_str = c_fun(value, False)
    if value.isupper():
        return c_fun_str

    new_name = ''
    l = len(c_fun_str)
    for i in range(l):
        c = c_fun_str[i]
        # When c is upper and no "_" appears before, do more checks
        if c.isupper() and (i > 0) and c_fun_str[i - 1] != "_":
            # Case 1: next string is lower
            # Case 2: previous string is digit
            if (i < (l - 1) and c_fun_str[i + 1].islower()) or \
            c_fun_str[i - 1].isdigit():
                new_name += '_'
        new_name += c
    return new_name.lstrip('_').upper()

def generate_enum_full_value(enum_name, enum_value):
    abbrev_string = _generate_enum_string(enum_name)
    value_string = _generate_enum_string(enum_value)
    return "%s_%s" % (abbrev_string, value_string)
