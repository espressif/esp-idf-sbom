# SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
Basic evaluation of expressions for configuration values specified with kconfig.
"""

from typing import Any, Dict, Union

import pyparsing as pp

# Parse actions used should not have any side effects, ensuring
# the safety of using packrat. Parsing expressions with brackets
# is very slow without caching.
pp.ParserElement.enablePackrat()

ppc = pp.pyparsing_common


def _boolit(operator: Union[bool, int, str]) -> bool:
    # kconfig-language.txt:
    #   Boolean and tristate symbols are simply converted into
    #   the respective expression values. All other symbol types
    #   result in 'n'.
    # This implementation uses only a boolean, not a tristate.
    return False if type(operator) is not bool else operator


def _eval_binary_operator(toks: pp.ParseResults, logical: bool=False) -> bool:
    operator_map = {
        '=': lambda o1, o2: o1 == o2,
        '!=': lambda o1, o2: o1 != o2,
        '<': lambda o1, o2: o1 < o2,
        '>': lambda o1, o2: o1 > o2,
        '<=': lambda o1, o2: o1 <= o2,
        '>=': lambda o1, o2: o1 >= o2,
        '&&': lambda o1, o2: o1 and o2,
        '||': lambda o1, o2: o1 or o2,
    }

    tokens = toks[0]
    operand1 = _boolit(tokens.pop(0)) if logical else tokens.pop(0)
    while len(tokens):
        # Evaluate all operators that have the same precedence level in this loop
        # The tokens may include, for example, ['VAR1', '>', 'VAR2', '>=', 'VAR3', '<', 'VAR4'].
        operator = tokens.pop(0)
        operand2 = _boolit(tokens.pop(0)) if logical else tokens.pop(0)
        if type(operand1) is not type(operand2):
            # No magic comparison. If the types don't match, just bail out.
            # Keep in mind that operands for logical operators will always
            # be boolean, so this situation should not occur for them.
            return False
        res = operator_map[operator](operand1, operand2)
        # Short-circuit evaluation
        if operator == '||' and res:
            return True
        if operator != '||' and not res:
            return False

        operand1 = operand2

    if operator == '||':
        return False

    return True


def _eval_comparison_operator(toks: pp.ParseResults) -> bool:
    return _eval_binary_operator(toks)


def _eval_logical_operator(toks: pp.ParseResults) -> bool:
    return _eval_binary_operator(toks, logical=True)


def _eval_unary_operator(toks: pp.ParseResults) -> bool:
    return not _boolit(toks[0][1])


# CPython versions before 3.8 do not allow annotated global variables to be used with forward references.
# https://bugs.python.org/issue34939
_variables: Dict[str, Any] = {}


def _eval_variable(toks: pp.ParseResults):
    # Return the variable value from sdkconfig.json or from predefined boolean variables.
    # If the variable is not found, return False by default.
    global _variables
    variable = toks[0]

    default_variables = {
        'true': True,
        'True': True,
        'false': False,
        'False': False,
    }

    return _variables.get(variable, default_variables.get(variable, False))


_variable = ppc.identifier.setParseAction(_eval_variable)
_hex = pp.Regex(r'0[xX][0-9a-fA-F]+').setParseAction(lambda t: int(t[0][2:], 16))
_number = ppc.number
_string = pp.QuotedString('"', '\\')

_expr = pp.infixNotation(
    _variable | _hex | _number | _string,
    [
        # Precedence according to Linux bison scripts/kconfig/parser.y
        ('!', 1, pp.opAssoc.RIGHT, _eval_unary_operator),
        (pp.oneOf('< > >= <='), 2, pp.opAssoc.LEFT, _eval_comparison_operator),
        (pp.oneOf('= !='), 2, pp.opAssoc.LEFT, _eval_comparison_operator),
        ('&&', 2, pp.opAssoc.LEFT, _eval_logical_operator),
        ('||', 2, pp.opAssoc.LEFT, _eval_logical_operator),
    ])


def set_variables(variables: Dict[str, Any]) -> None:
    global _variables
    _variables = variables


def evaluate(string: str) -> bool:
    try:
        res = _expr.parse_string(string, parse_all=True)
    except pp.exceptions.ParseException as e:
        raise RuntimeError(e)
    return _boolit(res[0])
