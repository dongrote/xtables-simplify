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
    reserved_targets = ('ACCEPT', 'DROP', 'RETURN', 'DNAT', 'CONNMARK', 'NFQUEUE', 'REDIRECT', 'REJECT', ' ', 'TCPMSS', 'NOTRACK')
    def __init__(self, primary_chains=[], extension_chains=[]):
        self.primary_chains = primary_chains
        self.extension_chains = extension_chains

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
                ret += '%s%s\t%s\n' % (prefix, target, criteria)
                ret += self.generate_chain_string(prefix+'\t', c)
            else:
                ret += self.generate_rule_string(prefix, *r)
        return ret

    def generate_rule_string(self, prefix, target, rule):
        return '%s%s\t%s\n' % (prefix, target, rule)

    def generate_pc_string(self, pc):
        ret = 'Chain %s (policy %s)\n' % (pc.name, pc.policy)
        ret += 'target\tprot opt source               destination\n'
        for r in pc.rules:
            target,criteria = r
            if target not in XTable.reserved_targets:
                c = self.get_chain_by_name(target)
                if c is None:
                    raise ValueError('Got None for target "%s"\n' % target)
                ret += '%s\t%s\n' % (target, criteria)
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
