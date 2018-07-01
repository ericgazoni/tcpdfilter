from scapy.all import IP, TCP, Ether
from tcpdfilter import (read_whitelist, filter_packets, 
                        WhitelistRule, packet_summary, PacketSummary)
import pytest

@pytest.fixture
def fake_capture():
    packets = (
        Ether() / IP(src='127.0.0.1', dst='8.8.8.8') / TCP(dport=53),
        Ether() / IP(src='127.0.0.1', dst='3.3.3.3') / TCP(dport=80),
        Ether() / IP(src='127.0.0.1', dst='2.2.2.2') / TCP(dport=443),
        Ether() / IP(src='127.0.0.1', dst='1.1.1.1') / TCP(dport=8080),
        Ether() / IP(src='8.8.8.8', dst='127.0.0.1') / TCP(dport=6000),
    )
    return packets


def test_it_matches_matching_rule_and_packet():
    rule = WhitelistRule(src='127.0.0.1', port=53, name='DNS from localhost')
    packet = Ether() / IP(src='127.0.0.1', dst='8.8.8.8') / TCP(dport=53)
    assert rule.matches(packet)

def test_it_matches_matching_rule_and_packet_from_real_example():
    rule = WhitelistRule(src='127.0.0.1', port=53, name='DNS from localhost')
    packet = Ether() / IP(src='127.0.0.1', dst='8.8.8.8') / TCP(sport=56543, 
                                                                dport=53)
    assert rule.matches(packet)

def test_it_does_not_match_unmatching_rule_and_packet():
    rule = WhitelistRule(src='127.0.0.1', port=443, name='HTTPS from localhost')
    packet = Ether() / IP(src='127.0.0.1', dst='8.8.8.8') / TCP(dport=53)
    assert not rule.matches(packet)

def test_it_filters_packets_correctly(fake_capture):
    definition = '''
- name: DNS to 8.8.8.8 from localhost
  src: 127.0.0.1
  dst: 8.8.8.8
  port: 53
    '''
    rules = read_whitelist(definition)
    output = filter_packets(packets=fake_capture, rules=rules)

    summary = list(output['whitelisted'])[0]
    assert summary == packet_summary(fake_capture[0], matching_rule=rules[0])

def test_it_produces_a_valid_summary():
    packet = Ether() / IP(src='127.0.0.1', dst='8.8.8.8') / TCP(dport=53, 
                                                                sport=2000)
    rule = WhitelistRule(src='127.0.0.1', port=443, name='HTTPS from localhost')

    output = packet_summary(packet=packet, matching_rule=rule)
    assert output == PacketSummary(src='127.0.0.1',
                                   dst='8.8.8.8',
                                   dport=53, 
                                   sport=2000,
                                   matching_rule=rule)

def test_it_deduplicates_packet_summaries():
    rule = WhitelistRule(src='127.0.0.1', port=443, name='HTTPS from localhost')

    summary1 = PacketSummary(src='127.0.0.1',
                             dst='8.8.8.8',
                             dport=53, 
                             sport=2000,
                             matching_rule=rule)
    summary2 = PacketSummary(src='127.0.0.1',
                             dst='8.8.8.8',
                             dport=53, 
                             sport=2000,
                             matching_rule=rule)
    summary3 = PacketSummary(src='127.0.0.1',
                             dst='9.9.9.9',
                             dport=53, 
                             sport=2000,
                             matching_rule=rule)
    assert len({summary1, summary2, summary3}) == 2