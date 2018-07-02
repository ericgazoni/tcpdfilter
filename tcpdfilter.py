import yaml
import attr
from argparse import ArgumentParser
from scapy.all import rdpcap
from prettytable import PrettyTable

import colorama
from colorama import Fore, Back, Style
colorama.init()

class UnreadableWhiteList(Exception):
    pass


@attr.s(cmp=True, hash=True)
class PacketSummary:
    src = attr.ib()
    dst = attr.ib()
    sport = attr.ib()
    dport = attr.ib()
    matching_rule = attr.ib()

    def __str__(self):
        text = 'src: {}, dst: {}, sport: {}, dport: {}'.format(self.src,
                                                               self.dst,
                                                               self.sport,
                                                               self.dport)
        if self.matching_rule:
            text = text + ' rule: {}'.format(self.matching_rule.name)
        return text

@attr.s(cmp=True, hash=True)
class WhitelistRule:
    name = attr.ib()
    src = attr.ib(default='*')
    dst = attr.ib(default='*')
    sport = attr.ib(default='*')
    dport = attr.ib(default='*')
    triggered = attr.ib(default=False)

    rule_to_packet_mapping = {
    }

    def __str__(self):
        return '{} > src:{} dst:{} sport:{} dport:{}'.format(
            self.name, self.src, self.dst, self.sport, self.dport
        )

    def matches(self, packet):
        if not 'IP' in packet:
            raise ValueError('this is not an IP packet')

        ip_layer = packet['IP']
        for attribute in ('src', 'dst', 'sport', 'dport'):
            rule_value = getattr(self, attribute)
            if rule_value != '*':
                packet_attribute = self.rule_to_packet_mapping.get(attribute,
                                                                   attribute)
                packet_value = getattr(ip_layer, packet_attribute)
                if packet_value != rule_value:
                    return False
        self.triggered = True
        return True

def parse_rule(definition):
    try:
        return WhitelistRule(**definition)
    except TypeError as ex:
        msg = 'mis-formatted rule: {}\n({})'
        raise UnreadableWhiteList(msg.format(definition, str(ex)))

def read_whitelist(stream):
    whitelist = yaml.load(stream)

    if not isinstance(whitelist, list):
        raise UnreadableWhiteList('whitelist does not contain valid rules')

    rules = []
    for definition in whitelist:
        rules.append(parse_rule(definition))

    return rules

def packet_summary(packet, matching_rule=None):
    return PacketSummary(src=packet['IP'].src,
                         dst=packet['IP'].dst,
                         sport=packet['IP'].sport,
                         dport=packet['IP'].dport,
                         matching_rule=matching_rule)

def filter_packets(packets, rules):
    output = {'whitelisted': set(), 'blacklisted': set()}

    for packet in packets:
        if not 'IP' in packet:
            continue

        for rule in rules:
            if rule.matches(packet):
                output['whitelisted'].add(packet_summary(packet,
                                                         matching_rule=rule))
                break
        else:
            output['blacklisted'].add(packet_summary(packet))

    return output

def main(whitelist_path, packet_capture_path):
    rules = read_whitelist(open(whitelist_path).read())
    packets = rdpcap(packet_capture_path)

    print(Fore.BLUE + '{} rules loaded'.format(len(rules)))
    print(Style.RESET_ALL)

    filtered_packets = filter_packets(packets, rules)

    print('Whitelisted:')
    table = PrettyTable(field_names=('src', 'dst', 'sport', 'dport', 'rule'))
    for col in table.align:
        table.align[col] = "r"
    table.align['rule'] = "l"
    for row in filtered_packets['whitelisted']:
        table.add_row(
            (row.src, row.dst, row.sport, row.dport, row.matching_rule.name)
        )
    print(Fore.GREEN + str(table))

    print(Style.RESET_ALL)
    print('Blacklisted:')

    table = PrettyTable(field_names=('src', 'dst', 'sport', 'dport'))
    for col in table.align:
        table.align[col] = "r"
    for row in filtered_packets['blacklisted']:
        table.add_row(
            (row.src, row.dst, row.sport, row.dport)
        )
    print(Fore.RED + str(table))
    print(Style.RESET_ALL)

    print('Rules not triggered:')
    for rule in rules:
        if not rule.triggered:
            print(Fore.YELLOW + str(rule))
    print(Style.RESET_ALL)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('whitelist')
    parser.add_argument('pcap_file')

    args = parser.parse_args()

    main(whitelist_path=args.whitelist, packet_capture_path=args.pcap_file)
