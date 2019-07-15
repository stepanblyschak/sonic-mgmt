'''
Description:

    This file contains the ACL test for SONiC testbed
    Implemented according to the https://github.com/Azure/SONiC/wiki/ACL-test-plan

Usage:
    Examples of how to use:

    ptf --test-dir acstests acltb_test.AclTest   --platform-dir ptftests  --platform remote
        -t "router_mac='e4:1d:2d:f7:d5:40';testbed_type='t1-lag';
        tor_ports='27,22,29,25,20,28,26,21,24,31,23,30,19,16,18,17';
        spine_ports='7,2,11,0,1,6,13,12,14,10,15,8,5,4,9,3';
        dst_ip_tor='172.16.1.0';dst_ip_tor_forwarded='172.16.2.0';dst_ip_tor_blocked='172.16.3.0';
        dst_ip_spine='192.168.0.0';dst_ip_spine_forwarded='192.168.0.16';dst_ip_spine_blocked='192.168.0.17'"
'''
from __future__ import print_function

import ptf
import ptf.packet as scapy
import ptf.testutils as testutils

from ptf.testutils import simple_tcp_packet
from ptf.testutils import simple_udp_packet
from ptf.testutils import simple_icmp_packet
from ptf.testutils import send_packet
from ptf.mask import Mask
from ptf.base_tests import BaseTest


class AclTest(BaseTest):
    '''
    @summary: ACL tests on testbed topo: t1
    '''

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()

    def setUp(self):
        '''
        @summary: Setup for the test
        '''

        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.testbed_type = self.test_params['testbed_type']
        self.src_ports = sorted([int(p) for p in self.test_params['src_ports'].split(',')])
        self.dst_ports = sorted([int(p) for p in self.test_params['dst_ports'].split(',')])
        self.dst_ip = self.test_params['default_dst_ip']
        self.src_ip = self.test_params['default_src_ip']
        self.action = self.test_params['action']
        self.proto = self.test_params['proto'].upper()

        if self.proto == 'TCP':
            self.init_tcp_pair()
        elif self.proto == 'UDP':
            self.init_udp_pair()
        elif self.proto == 'ICMP':
            self.init_icmp_pair()
        else:
            raise ValueError('Protocol {} not handled in PTF test'.format(self.proto))

        self.current_src_port_idx = 0  # An index for choosing a port for injecting packet

    def init_tcp_pair(self):
        self.pkt = simple_tcp_packet(
            eth_dst=self.router_mac,
            eth_src=self.dataplane.get_mac(0, 0),
            ip_src=self.src_ip,
            ip_dst=self.dst_ip,
            tcp_sport=0x4321,
            tcp_dport=0x51,
            ip_ttl=64
        )

        self.exp_pkt = simple_tcp_packet(
            eth_dst=self.dataplane.get_mac(0, 0),
            eth_src=self.router_mac,
            ip_src=self.src_ip,
            ip_dst=self.dst_ip,
            tcp_sport=0x4321,
            tcp_dport=0x51,
            ip_ttl=63
        )

    def init_udp_pair(self):
        self.pkt = simple_udp_packet(
            eth_dst=self.router_mac,
            eth_src=self.dataplane.get_mac(0, 0),
            ip_src=self.src_ip,
            ip_dst=self.dst_ip,
            udp_sport=1234,
            udp_dport=80,
            ip_ttl=64
        )

        self.exp_pkt = simple_udp_packet(
            eth_dst=self.dataplane.get_mac(0, 0),
            eth_src=self.router_mac,
            ip_src=self.src_ip,
            ip_dst=self.dst_ip,
            udp_sport=1234,
            udp_dport=80,
            ip_ttl=63
        )

    def init_icmp_pair(self):
        self.pkt = simple_icmp_packet(
            eth_dst=self.router_mac,
            eth_src=self.dataplane.get_mac(0, 0),
            ip_src=self.src_ip,
            ip_dst=self.dst_ip,
            icmp_type=8,
            icmp_code=0,
            ip_ttl=64
        )

        self.exp_pkt = simple_icmp_packet(
            eth_dst=self.dataplane.get_mac(0, 0),
            eth_src=self.router_mac,
            ip_src=self.src_ip,
            ip_dst=self.dst_ip,
            icmp_type=8,
            icmp_code=0,
            ip_ttl=63
        )

    def _select_src_port(self, src_ports):
        """
        @summary: Choose a source port from list source ports in a round robin way
        @return: Source port number picked from list of source ports
        """
        if len(src_ports) == 0:
            return None

        self.current_src_port_idx = self.current_src_port_idx % len(src_ports)  # In case the index is out of range

        port = src_ports[self.current_src_port_idx]
        self.current_src_port_idx = (self.current_src_port_idx + 1) % len(src_ports)
        return port

    def runSendReceiveTest(self, pkt2send, src_ports, pkt2recv, dst_ports, pkt_expected):
        """
        @summary Send packet and verify it is received/not received on the expected ports
        @param pkt2send: The packet that will be injected into src_port
        @param src_ports: The port into which the pkt2send will be injected
        @param pkt2recv: The packet that will be received on one of the dst_ports
        @param dst_ports: The ports on which the pkt2recv may be received
        @param pkt_expected: Indicated whether it is expected to receive the pkt2recv on one of the dst_ports
        """

        masked2recv = Mask(pkt2recv)
        masked2recv.set_do_not_care_scapy(scapy.Ether, "dst")
        masked2recv.set_do_not_care_scapy(scapy.Ether, "src")

        # Choose a source port from list of source ports
        src_port = self._select_src_port(src_ports)

        # Send the packet and poll on destination ports
        send_packet(self, src_port, pkt2send)
        if pkt_expected:
            testutils.verify_packet_any_port(self, masked2recv, dst_ports)
        else:
            testutils.verify_no_packet_any(self, masked2recv, dst_ports)

    def runTest(self):
        self.runSendReceiveTest(self.pkt, self.src_ports, self.exp_pkt, self.dst_ports, self.action == 'forward')

class Unmatched(AclTest):
    pass

class SourceIpMatch(AclTest):
    def setUp(self):
        super(SourceIpMatch, self).setUp()
        self.pkt['IP'].src = self.test_params['source_ip']
        self.exp_pkt['IP'].src = self.test_params['source_ip']

class DestIpMatch(AclTest):
    def setUp(self):
        self.pkt['IP'].dst = self.test_params['destination_ip']
        self.exp_pkt['IP'].dst = self.test_params['destination_ip']

class L4SourcePortMatch(AclTest):
    def runTest(self):
        self.pkt[self.proto].sport = int(self.test_params['source_port'], 0)
        self.exp_pkt[self.proto].sport = int(self.test_params['source_port'], 0)

class L4DestPortMatch(AclTest):
    def runTest(self):
        self.pkt[self.proto].dport = int(self.test_params['destination_port'], 0)
        self.exp_pkt[self.proto].dport = int(self.test_params['destination_port'], 0)

class IpProtocolMatch(AclTest):
    def runTest(self):
        self.pkt['IP'].proto = int(self.test_params['protocol'], 0)
        self.exp_pkt['IP'].proto = int(self.test_params['protocol'], 0)

class TcpFlagsMatch(AclTest):
    def runTest(self):
        self.pkt['TCP'].flags = int(self.test_params['flags'], 0)
        self.exp_pkt['TCP'].flags = int(self.test_params['flags'], 0)
