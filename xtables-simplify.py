#!/usr/bin/env python
import sys

class Chain(object):
    def __init__(self, name):
        self.name = name
        self.rules = []

    def add_rule(self, target, rule):
        self.rules.append((target,rule.rstrip()))

    def __repr__(self):
        return '%s -- %r' % (self.name, self.rules)

class PrimaryChain(Chain):
    def __init__(self, name, policy):
        self.policy = policy
        super(PrimaryChain, self).__init__(name)

    def __repr__(self):
        return '%s %s -- %r' % (self.name, self.policy, self.rules)

class XTable(object):
    reserved_targets = ('ACCEPT', 'DROP', 'RETURN', 'DNAT', 'CONNMARK', 'NFQUEUE', 'REDIRECT', 'REJECT', ' ', 'TCPMSS', 'NOTRACK', 'SNAT', 'MASQUERADE')
    def __init__(self, primary_chains=[], extension_chains=[]):
        self.primary_chains = primary_chains
        self.extension_chains = extension_chains
        self.calculate_target_pad_length()

    @staticmethod
    def max_target_name_length(chainlist):
        chains = filter(lambda c: len(c.rules) > 0, chainlist)
        return max(
            reduce(
                lambda tlens,m: max(max(tlens),m),
                map(lambda c: map(lambda cr: len(cr[0]),c.rules),
                    chains)))

    def calculate_target_pad_length(self):
        self.target_pad_length = 2 + max(
            XTable.max_target_name_length(self.primary_chains),
            XTable.max_target_name_length(self.extension_chains))

    def target_pad_space(self, target):
        return ' '*(self.target_pad_length - len(target))

    def get_chain_by_name(self, chain_name):
        for c in self.extension_chains:
            if c.name == chain_name:
                return c
        return None

    def generate_chain_string(self, prefix, chain):
        ret = ''
        if chain is None:
            return ret
        for r in chain.rules:
            target,criteria = r
            if target not in XTable.reserved_targets:
                c = self.get_chain_by_name(target)
                if c is None:
                    raise ValueError('Got None for target "%s", chain %r, rule %r\n' % (target,chain,r))
                ret += '%s%s%s%s\n' % (prefix, target, self.target_pad_space(target), criteria)
                ret += self.generate_chain_string(prefix+'\t', c)
            else:
                ret += self.generate_rule_string(prefix, *r)
        return ret

    def generate_rule_string(self, prefix, target, rule):
        return '%s%s%s%s\n' % (prefix, target, self.target_pad_space(target), rule)

    def generate_pc_string(self, pc):
        ret = 'Chain %s (policy %s)\n' % (pc.name, pc.policy)
        ret += 'target%sprot opt source               destination\n' % self.target_pad_space('target')
        for r in pc.rules:
            target,criteria = r
            if target not in XTable.reserved_targets:
                c = self.get_chain_by_name(target)
                if c is None:
                    raise ValueError('Got None for target "%s"\n' % target)
                ret += '%s%s%s\n' % (target, self.target_pad_space(target), criteria)
                ret += self.generate_chain_string('\t', c)
            else:
                ret += self.generate_rule_string('', *r)
        ret += '\n'
        return ret

    def __str__(self):
        ret = ''
        for pc in self.primary_chains:
            ret += self.generate_pc_string(pc)
        return ret

    def __repr__(self):
        ret = ''
        for pc in self.primary_chains:
            ret += '%r\n\n' % pc
        for c in self.extension_chains:
            ret += '%r\n\n' % c
        return ret

def parse_xtables_output(output):
    primary_chains = []
    other_chains = []
    current_chain = None
    for line in output.splitlines():
        if len(line) is 0 or line.startswith('target'):
            continue
        if line.startswith('Chain ') and 'policy' in line:
            fields = line.split()
            pc = PrimaryChain(fields[1], fields[3][:-1])
            primary_chains.append(pc)
            current_chain = pc
            continue
        if line.startswith('Chain '):
            fields = line.split()
            c = Chain(fields[1])
            other_chains.append(c)
            current_chain = c
            continue
        # from here on out, we're dealing with a rule
        if line.startswith(' '):
            fields = (' ', line)
        else:
            fields = line.split(None, 1)
        current_chain.add_rule(*fields)
    return XTable(primary_chains, other_chains)

def main():
    xtable = parse_xtables_output(sys.stdin.read())
    print xtable

if '__main__' == __name__:
    sys.exit(main())
