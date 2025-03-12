# SPDX-FileCopyrightText: 2024-2025 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
'''
Implementation of NISTIR 7696, Common Platform Enumeration: Name Matching Specification Version 2.3
for the formatted string binding

NISTIR7695: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
NISTIR7696: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
NISTIR7698: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7698.pdf
'''

import re

# NISTIR7695: Figure 6-3. ABNF for Formatted String Binding
# Allowed values in CPE attribute in the formatted string binding of WFN
# Note that wild cards can only be at the beginning and end of the attribute value.
RE_CPE_AV_VALID = re.compile(r'^(\*|\?+)?((?:[a-zA-Z0-9._-])|(?:\\[\\*?!\"#$%&\'()+,/:;<=>@[\]^`{|}~]))+(\*|\?+)?$')
RE_CPE_AV_WILDCARDS = ''

# NISTIR7696: Table 6-1: CPE Name Matching Set Relations
AV_REL_UNDEFINED = 0x00
AV_REL_SUPERSET = 0x01
AV_REL_SUBSET = 0x02
AV_REL_EQUAL = 0x03
AV_REL_DISJOINT = 0x04

# NISTIR7696: 6.1 Attribute Comparison Relations
# Losely based on attribude notation
# 1. ANY and NA are logical values as defined in [CPE23-N:5.3.1]
# 2. i is a wildcard-free attribute-value string, e.g., "foo"
# 3. k is a wildcard-free attribute-value string that is not identical to i, e.g., "bar"
# 4. m + wild cards is an attribute-value string containing a legal combination of unquoted question
#    mark or asterisk wild cards at the beginning and/or the end of the string, e.g., "*b??
AV_TYPE_ANY = 0x01
AV_TYPE_NA = 0x02
AV_TYPE_STR = 0x03
AV_TYPE_WC = 0x04


def is_av_valid(av: str) -> bool:
    if av in ['*', '?']:
        return True
    return True if RE_CPE_AV_VALID.match(av) else False


def has_av_wildcards(av: str) -> bool:
    match = RE_CPE_AV_VALID.match(av)
    if match and (match.group(1) or match.group(3)):
        return True
    return False


def get_av_type(av: str) -> int:
    if av == '*':
        return AV_TYPE_ANY
    elif av == '-':
        return AV_TYPE_NA
    elif has_av_wildcards(av):
        return AV_TYPE_WC
    else:
        return AV_TYPE_STR


def av_to_re(av: str) -> str:
    """Transform the attribute value into a regular expression"""

    # NISTIR7696: 6.3 Wild Card Attribute Comparison
    # The unquoted asterisk (*) character is a wild card for zero or more characters in the
    # target value, and the unquoted question mark (?) character is a wild card for zero or
    # one characters in the target value.
    match = RE_CPE_AV_VALID.match(av)
    # This should be called once the CPE has been validated, so match shouldn't be None.
    assert match is not None
    head = match.group(1) or ''
    tail = match.group(3) or ''
    body = av[len(head) if head else 0: -len(tail) if tail else len(av)]

    # Substitute AV wildcards with regular expressions
    # Wild cards are permitted solely at the start(head) and end(tail) of the attribute value.
    head = head.replace('*', '.*').replace('?', '.?')
    tail = tail.replace('*', '.*').replace('?', '.?')

    # All elements in the body should be treated as literal, so escape any special characters
    # that might be used by regex.
    body = re.escape(body)

    return '^' + head + body + tail + '$'


def is_cpe_valid(cpe: str) -> bool:
    cpe_parts = cpe.split(':')
    if len(cpe_parts) != 13:
        return False
    if cpe_parts[0] != 'cpe':
        return False
    if cpe_parts[1] != '2.3':
        return False
    if cpe_parts[2] not in ['h','o','a', '*', '-']:
        return False

    for av in cpe_parts[2:]:
        if not is_av_valid(av):
            return False

    return True


def compare_avs(src_av: str, tgt_av: str):
    src_av = src_av.lower()
    tgt_av = tgt_av.lower()
    src_av_type = get_av_type(src_av)
    tgt_av_type = get_av_type(tgt_av)

    # NISTIR769: Table 6-2: Enumeration of Attribute Comparison Set Relations
    # Section 7.3 CPE Name Matching Pseudocode: Support Functions includes pseudocode
    # with aggregated conditions, but here, most of the relations are kept separate to
    # enhance readability.

    # 4,8,11,17 (ANY | NA | STR | WC) & WC = UNDEFINED
    if tgt_av_type == AV_TYPE_WC:
        # This is an undefined relation.
        return AV_REL_UNDEFINED

    # 1 ANY & ANY = EQUAL
    if src_av_type == AV_TYPE_ANY and tgt_av_type == AV_TYPE_ANY:
        return AV_REL_EQUAL

    # 2 ANY & NA = SUPERSET
    if src_av_type == AV_TYPE_ANY and tgt_av_type == AV_TYPE_NA:
        return AV_REL_SUPERSET

    # 3 ANY & STR = SUPERSET
    if src_av_type == AV_TYPE_ANY and tgt_av_type == AV_TYPE_STR:
        return AV_REL_SUPERSET

    # 5 NA & ANY = SUBSET
    if src_av_type == AV_TYPE_NA and tgt_av_type == AV_TYPE_ANY:
        return AV_REL_SUBSET

    # 6 NA & NA = EQUAL
    if src_av_type == AV_TYPE_NA and tgt_av_type == AV_TYPE_NA:
        return AV_REL_EQUAL

    # 7 NA & STR = DISJOINT
    if src_av_type == AV_TYPE_NA and tgt_av_type == AV_TYPE_STR:
        return AV_REL_DISJOINT

    # 9,10 STR & STR = EQUAL | DISJOINT
    if src_av_type == AV_TYPE_STR and tgt_av_type == AV_TYPE_STR:
        if src_av == tgt_av:
            return AV_REL_EQUAL
        else:
            return AV_REL_DISJOINT

    # 12 STR & NA = DISJOINT
    if src_av_type == AV_TYPE_STR and tgt_av_type == AV_TYPE_NA:
        return AV_REL_DISJOINT

    # 13 STR & ANY = SUBSET
    if src_av_type == AV_TYPE_STR and tgt_av_type == AV_TYPE_ANY:
        return AV_REL_SUBSET

    # 14 WC & STR = SUPERSET | DISJOINT
    if src_av_type == AV_TYPE_WC and tgt_av_type == AV_TYPE_STR:
        src_av_re = av_to_re(src_av)
        if re.match(src_av_re, tgt_av):
            return AV_REL_SUPERSET
        return AV_REL_DISJOINT

    # 15 WC & ANY = SUBSET
    if src_av_type == AV_TYPE_WC and tgt_av_type == AV_TYPE_ANY:
        return AV_REL_SUBSET

    # 16 WC & NA = SUBSET
    if src_av_type == AV_TYPE_WC and tgt_av_type == AV_TYPE_NA:
        return AV_REL_DISJOINT

    assert False


def get_relation_set(source: str, target: str) -> list:
    # NISTIR7696: 6.1 Attribute Comparison Relations
    # This implements the first part of the CPE name matching.
    rel_set: list = []
    source_parts = source.split(':')
    target_parts = target.split(':')
    for av_id in range(2, 13):
        source_av = source_parts[av_id]
        target_av = target_parts[av_id]
        rel_set.append(compare_avs(source_av, target_av))

    return rel_set


def compare(source: str, target: str) -> int:
    # NISTIR7696: 6.2 Name Comparison Relations
    # This implements the second part of the CPE name matching.
    if not is_cpe_valid(source):
        raise RuntimeError(f'CPE {source} not valid')
    if not is_cpe_valid(target):
        raise RuntimeError(f'CPE {target} not valid')

    rel_set = get_relation_set(source, target)
    if AV_REL_UNDEFINED in rel_set:
        raise RuntimeError(f'CPE comparison of target: {target} and source: {source} has undefined relation')

    # NISTIR7696: Table 6-4: Required CPE Name Comparison Relations
    # 1 If any attribute relation is DISJOINT
    if AV_REL_DISJOINT in rel_set:
        return AV_REL_DISJOINT

    # 2 If all attribute relations are EQUAL
    if rel_set == [AV_REL_EQUAL] * 11:
        return AV_REL_EQUAL

    # 3 If all attribute relations are SUBSET or EQUAL
    if AV_REL_SUPERSET not in rel_set:
        return AV_REL_SUBSET

    # 4 If all attribute relations are SUPERSET or EQUAL
    if AV_REL_SUBSET not in rel_set:
        return AV_REL_SUPERSET

    # SUBSET and SUPERSET
    # It appears that the documentation does not clarify what should be returned in this situation.
    return AV_REL_DISJOINT


def match(source: str, target: str) -> bool:
    # NISTIR7696: 6.2 Name Comparison Relations
    # Table 6-4: Required CPE Name Comparison Relations
    # CPE implementers who wish to emulate the functionality of the CPE 2.2
    # Matching algorithm should note that name comparison numbers 1 and 3 in
    # Table 6-4 are equivalent to a final result of FALSE in CPE 2.2, while
    # name comparison numbers 2 and 4 are equivalent to a CPE 2.2 result of
    # TRUE.

    res = compare(source, target)
    if res == AV_REL_EQUAL or res == AV_REL_SUPERSET:
        return True

    return False
