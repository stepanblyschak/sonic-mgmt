import ptf
import pytest
import time
import logging

from common import reload, reboot
from abc import ABCMeta, abstractmethod

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.acl

DST_IP_TOR             = '172.16.1.0'
DST_IP_TOR_FORWARDED   = '172.16.2.0'
DST_IP_TOR_BLOCKED     = '172.16.3.0'
DST_IP_SPINE           = '192.168.0.0'
DST_IP_SPINE_FORWARDED = '192.168.0.16'
DST_IP_SPINE_BLOCKED   = '192.168.0.17'

def generate_backup_name(filename):
    """
    generate backup file name base on @filename
    :param filename: name of the file to be backed up
    :return: backup file name
    """

    return '{}.bak.{}'.format(filename, time.strftime('%Y%m%d-%H%M%S'))

@pytest.fixture(scope='module')
def setup(dut, testbed):
    """
    setup fixture gathers all test required information from DUT facts and testbed
    :param dut: DUT host object
    :param testbed: Testbed object
    :return: dictionary with all test required information
    """

    tor_ports = []
    spine_ports = []
    tor_ports_ids = []
    spine_ports_ids = []
    port_channels = []
    acl_table_ports = []

    # gather ansible facts
    mg_facts = dut.minigraph_facts(host=dut.hostname)['ansible_facts']

    # get the list of TOR/SPINE ports
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        port_id = mg_facts['minigraph_port_indices'][dut_port]
        if 'T0' in neigh['name']:
            tor_ports.append(dut_port)
            tor_ports_ids.append(port_id)
        elif 'T2' in neigh['name']:
            spine_ports.append(dut_port)
            spine_ports_ids.append(port_id)

    # get the list of port channels
    for port_channel in mg_facts['minigraph_portchannels']:
        port_channels.append(port_channel)

    # get the list of port to be combined to ACL tables
    acl_table_ports += tor_ports
    if testbed['topo'] in ('t1-lag', 't1-64-lag'):
        acl_table_ports += port_channels
    else:
        acl_table_ports += spine_ports

    # initialize name for config_db.json backup file
    config_db_backup = generate_backup_name('config_db.json')

    host_facts  = dut.setup()['ansible_facts']

    return {
        'config_db_backup'      : config_db_backup,
        'router_mac'            : host_facts['ansible_Ethernet0']['macaddress'],
        'dut_tmp_dir'           : '/tmp/acl/',
        'tor_ports'             : tor_ports,
        'spine_ports'           : spine_ports,
        'tor_ports_ids'         : tor_ports_ids,
        'spine_ports_ids'       : spine_ports_ids,
        'port_channels'         : port_channels,
        'acl_table_ports'       : acl_table_ports,
        'dst_ip_tor'            : DST_IP_TOR,
        'dst_ip_tor_forwarded'  : DST_IP_TOR_FORWARDED,
        'dst_ip_tor_blocked'    : DST_IP_TOR_BLOCKED,
        'dst_ip_spine'          : DST_IP_SPINE,
        'dst_ip_spine_forwarded': DST_IP_SPINE_FORWARDED,
        'dst_ip_spine_blocked'  : DST_IP_SPINE_BLOCKED,
    }

@pytest.fixture(scope='module', params=['ingress', 'egress'])
def stage(request):
    """
    small fixture to parametrize test for ingres/egress stage testing
    :param request: pytest request
    :return: stage parameter
    """

    if request.param not in ('ingress', 'egress'):
        raise ValueError("Stage has to be ingress/egress")

    stage = request.param

    if stage == 'ingress' and not request.config.getoption('--acl-ingress'):
        pytest.skip('Only ACL egress tests requested')

    if stage == 'egress' and not request.config.getoption('--acl-egress'):
        pytest.skip('Only ACL ingress tests requested')

    return stage

@pytest.fixture(scope='module')
def acl_table_config(dut, setup, stage):
    """
    generate ACL table configuration files and deploy them on DUT;
    after test run cleanup artifacts on DUT
    :param dut: DUT host object
    :param setup: setup parameters
    :param stage: stage
    :return: dictionary of table name and matching configuration file
    """

    # Initialize data for ACL tables
    tables_map = {
        'ingress': 'DATAINGRESS',
        'egress': 'DATAEGRESS',
    }

    acl_table_name = tables_map[stage]
    tmp = setup['dut_tmp_dir']

    logger.debug('creating temporary folder for test {}'.format(tmp))
    dut.command("mkdir -p {}".format(tmp))

    # copy rules remove configuration
    dut.copy(src='acl/files/acl_rules_del.json',
             dest='{dir}/'.format(dir=tmp)
    )

    extra_vars = {
        'acl_table_name':  acl_table_name,
        'acl_table_ports': setup['acl_table_ports'],
        'acl_table_stage': stage,
        'acl_table_type': 'L3',
    }

    dut.host.options['variable_manager'].extra_vars = extra_vars

    logger.debug('generate config for ACL table {table_name}'.format(table_name=acl_table_name))
    dest_file = '{dir}/acl_table_{name}.json'.format(dir=tmp, name=acl_table_name)
    dut.template(src='acl/templates/acltb_table.j2',
                 dest=dest_file,
    )

    yield {
        'acl_table_name': acl_table_name,
        'acl_config_file': dest_file,
    }

    logger.debug('removing {}'.format(tmp))
    dut.command('rm -rf {}'.format(tmp))

@pytest.fixture(scope='module')
def acl_table(dut, acl_table_config):
    conf = acl_table_config['acl_config_file']

    logger.debug('creating ACL tables: applying {conf}'.format(conf=conf))
    dut.command('sonic-cfggen -j {conf} --write-to-db'.format(conf=conf))

    yield acl_table_config

    # TODO: restore saved config_db.json
    logger.info('reloading config to cleanup')
    reload(dut)


class BaseAclTest(object):
    """
    Base class for ACL rules testing.
    Derivatives have to provide @setup_rules method to prepare DUT for ACL traffic test and
    optionally override @teardown_rules which base implementation is simply applying empty ACL rules
    configuration file
    """
    __metaclass__ = ABCMeta

    ACL_COUNTERS_UPDATE_INTERVAL = 10 # seconds

    @abstractmethod
    def setup_rules(self, dut, setup, acl_table):
        """
        setup rules for test
        :param dut: dut host
        :param setup: setup information
        :param acl_table: acl table creating fixture
        :return:
        """

        pass

    def teardown_rules(self, dut):
        """
        teardown ACL rules after test by applying empty configuration
        :param dut: DUT host object
        :return:
        """

        logger.debug('removing ACL rules')
        dut.command('config acl update full /tmp/acl/acl_rules_del.json')

    @pytest.fixture(scope='class', autouse=True)
    def acl_rules(self, dut, setup, acl_table):
        """
        setup/teardown ACL rules based on test class requirements
        :param dut: DUT host object
        :param setup: setup information
        :param acl_table: table creating fixture
        :return:
        """

        try:
            self.setup_rules(dut, setup, acl_table)
            yield
        finally:
            self.teardown_rules(dut)

    @pytest.yield_fixture(scope='class', autouse=True)
    def counters_sanity_check(self, dut, acl_rules, acl_table):
        """
        counters sanity check after traffic test cases.
        This fixture yields python list of rule IDs which test case should extend if
        the RULE is required to check for increased counters.
        After test cases passed the fixture will wait for ACL counters to update
        and check if counters for each rule in the list of rules were increased.
        :param dut: DUT host object
        :param acl_rules: rules creating fixture
        :param acl_table: table creating fixture
        :return:
        """

        table_name = acl_table['acl_table_name']
        acl_facts_before_traffic = dut.acl_facts()['ansible_facts']['ansible_acl_facts'][table_name]['rules']
        rule_list = []
        yield rule_list

        if not rule_list:
            return

        # wait for orchagent to update ACL counters
        time.sleep(self.ACL_COUNTERS_UPDATE_INTERVAL)

        acl_facts_after_traffic = dut.acl_facts()['ansible_facts']['ansible_acl_facts'][table_name]['rules']

        assert len(acl_facts_after_traffic) == len(acl_facts_before_traffic)

        for rule in rule_list:
            rule = 'RULE_{}'.format(rule)
            counters_after = acl_facts_after_traffic[rule]
            counters_before = acl_facts_before_traffic[rule]
            assert counters_after['packets_count'] > counters_before['packets_count']
            assert counters_after['bytes_count'] > counters_before['bytes_count']

    @pytest.fixture(params=['tor->spine', 'spine->tor'])
    def direction(self, request):
        """
        used to parametrized test cases on direction
        :param request: pytest request object
        :return: direction
        """

        return request.param

    @pytest.fixture
    def traffic_test_case(self, request, direction):
        """
        generate traffic test cases based on test case name passed in request.param and direction
        :param request: pytest request object
        :param direction: direction (spine->tor, tor->spine)
        :return: test case information dictionary
        """

        test_cases = {
            'default_block': {
                'ptf_test_class': 'Unmatched',
                'action': 'drop',
                'proto': 'tcp',
            },
            'source_ip_match_accept': {
                'ptf_test_class': 'SourceIpMatch',
                'action': 'forward',
                'proto': 'tcp',
                'source_ip': '20.0.0.2',
                'rule_ids': [1],
            },
            'dest_ip_match_accept': {
                'ptf_test_class': 'DestIpMatch',
                'action': 'forward',
                'proto': 'tcp',
                'destination_ip': DST_IP_TOR_FORWARDED if direction == 'spine->tor' else DST_IP_SPINE_FORWARDED,
                'rule_ids': [2 if direction == 'spine->tor' else 3],
            },
            'l4_source_port_match_accept': {
                'ptf_test_class': 'L4SourcePortMatch',
                'action': 'forward',
                'proto': 'tcp',
                'source_port': 0x120D,
                'rule_ids': [4],
            },
            'l4_dest_port_match_accept': {
                'ptf_test_class': 'L4DestPortMatch',
                'action': 'forward',
                'proto': 'tcp',
                'destination_port': 0x1217,
                'rule_ids': [9],
            },
            'ip_protocol_match_accept': {
                'ptf_test_class': 'IpProtocolMatch',
                'action': 'forward',
                'proto': 'tcp',
                'protocol': 0x7E,
                'rule_ids': [5],
            },
            'tcp_flags_match_accept': {
                'ptf_test_class': 'TcpFlagsMatch',
                'action': 'forward',
                'proto': 'tcp',
                'flags': 0x1B,
                'rule_ids': [6],
            },
            'l4_source_port_range_accept': {
                'ptf_test_class': 'L4SourcePortMatch',
                'action': 'forward',
                'proto': 'tcp',
                'source_port': 0x123A,
                'rule_ids': [10],
            },
            'l4_dest_port_range_accept': {
                'ptf_test_class': 'L4DestPortMatch',
                'action': 'forward',
                'proto': 'tcp',
                'destination_port': 0x123B,
                'rule_ids': [11],
            },
            'rules_priority_block': {
                'ptf_test_class': 'SourceIpMatch',
                'action': 'drop',
                'proto': 'tcp',
                'source_ip': '20.0.0.3',
                'rule_ids': [7],
            },
            'icmp_source_ip_match_accept': {
                'ptf_test_class': 'SourceIpMatch',
                'action': 'forward',
                'proto': 'icmp',
                'source_ip': '20.0.0.4',
                'rule_ids': [12],
            },
            'udp_source_ip_match_accept': {
                'ptf_test_class': 'SourceIpMatch',
                'action': 'forward',
                'proto': 'udp',
                'source_ip': '20.0.0.4',
                'rule_ids': [13],
            },
            'source_ip_match_block': {
                'ptf_test_class': 'SourceIpMatch',
                'action': 'drop',
                'proto': 'tcp',
                'source_ip': '20.0.0.6',
                'rule_ids': [14],
            },
            'dest_ip_match_block': {
                'ptf_test_class': 'DestIpMatch',
                'action': 'drop',
                'proto': 'tcp',
                'destination_ip': DST_IP_TOR_BLOCKED if direction == 'spine->tor' else DST_IP_SPINE_BLOCKED,
                'rule_ids': [15 if direction == 'spine->tor' else 16],
            },
            'l4_source_port_match_block': {
                'ptf_test_class': 'L4SourcePortMatch',
                'action': 'drop',
                'proto': 'tcp',
                'source_port': 0x1271,
                'rule_ids': [17],
            },
            'l4_dest_port_match_block': {
                'ptf_test_class': 'L4DestPortMatch',
                'action': 'drop',
                'proto': 'tcp',
                'destination_port': 0x127B,
                'rule_ids': [22],
            },
            'ip_protocol_match_block': {
                'ptf_test_class': 'IpProtocolMatch',
                'action': 'drop',
                'proto': 'tcp',
                'protocol': 0x7F,
                'rule_ids': [18],
            },
            'tcp_flags_match_block': {
                'ptf_test_class': 'TcpFlagsMatch',
                'action': 'drop',
                'proto': 'tcp',
                'flags': 0x24,
                'rule_ids': [19],
            },
            'l4_source_port_range_block': {
                'ptf_test_class': 'L4SourcePortMatch',
                'action': 'drop',
                'proto': 'tcp',
                'source_port': 0x129E,
                'rule_ids': [23],
            },
            'l4_dest_port_range_block': {
                'ptf_test_class': 'L4DestPortMatch',
                'action': 'drop',
                'proto': 'tcp',
                'destination_port': 0x129F,
                'rule_ids': [24],
            },
            'rules_priority_accept': {
                'ptf_test_class': 'SourceIpMatch',
                'action': 'forward',
                'proto': 'tcp',
                'source_ip': '20.0.0.7',
                'rule_ids': [20],
            },
            'icmp_source_ip_match_block': {
                'ptf_test_class': 'SourceIpMatch',
                'action': 'forward',
                'proto': 'icmp',
                'source_ip': '20.0.0.8',
                'rule_ids': [25],
            },
            'udp_source_ip_match_block': {
                'ptf_test_class': 'SourceIpMatch',
                'action': 'drop',
                'proto': 'udp',
                'source_ip': '20.0.0.8',
                'rule_ids': [26],
            },
        }

        try:
            test_case = test_cases[request.param]
        except KeyError:
            raise ValueError('invalid test case passed {}'.format(test_case))

        def get_src_ports():
            return setup['tor_ports_ids'] if direction == 'tor->spine' else setup['spine_ports_ids']

        def get_dst_ports():
            return setup['spine_ports_ids'] if direction == 'tor->spine' else setup['tor_ports_ids']

        def get_dst_ip():
            return setup['dst_ip_spine'] if direction == 'tor->spine' else setup['dst_ip_tor']

        test_case['src_ports'] = ','.join([str(id) for id in get_src_ports()])
        test_case['dst_ports'] = ','.join([str(id) for id in get_dst_ports()])
        test_case['default_dst_ip'] = get_dst_ip()
        test_case['default_src_ip'] = '20.0.0.1'

        return test_case


    # parametrize with a list of test cases names by indirectly applying 'test_case' fixture
    @pytest.mark.parametrize('traffic_test_case',
        [
            'default_block',
            'source_ip_match_accept',
            'dest_ip_match_accept',
            'l4_source_port_match_accept',
            'l4_dest_port_match_accept',
            'ip_protocol_match_accept',
            'tcp_flags_match_accept',
            'l4_source_port_range_accept',
            'l4_dest_port_range_accept',
            'rules_priority_accept',
            'icmp_source_ip_match_accept',
            'udp_source_ip_match_accept',
            'source_ip_match_block',
            'dest_ip_match_block',
            'l4_source_port_match_block',
            'l4_dest_port_match_block',
            'ip_protocol_match_block',
            'tcp_flags_match_block',
            'l4_source_port_range_block',
            'l4_dest_port_range_block',
            'rules_priority_block',
            'icmp_source_ip_match_block',
            'udp_source_ip_match_block',
        ],
        indirect=True,
    )
    def test_traffic(self,
                     setup,
                     ptfhost,
                     testbed,
                     counters_sanity_check,
                     traffic_test_case):
        '''
        run ptf traffic test case
        :param setup: setup parameters
        :param ptfhost: PTF host object
        :param testbed: testbed information
        :param counters_sanity_check: ACL counters check fixture
        :param traffic_test_case: test case information
        :return:
        '''

        rule_ids = traffic_test_case.pop('rule_ids', [])
        test_class = traffic_test_case.pop('ptf_test_class')

        # general ptf parameters
        params = {
            'testbed_type' : testbed['topo'],
            'router_mac'   : setup['router_mac'],
        }
        # Update with test_case dictionary
        params.update({k: str(traffic_test_case[k]) for k in traffic_test_case})

        ptf.ptf_runner(ptfhost,
                   'acstests',
                   'acltb_test.{}'.format(test_class),
                   platform_dir='ptftests',
                   params=params,
                   log_file='/tmp/acltb_test.{}.log'.format(test_class)
        )
        counters_sanity_check.extend(rule_ids)


class TestBasicAcl(BaseAclTest):
    """
    Basic ACL rules traffic tests.
    Setup rules using full update, run traffic tests cases.
    """

    @pytest.fixture(scope='class', autouse=True)
    def skip(self, request):
        """
        skip test class fixture based on CLI
        :param request: pytest request object
        :return:
        """

        if not request.config.getoption('--acl-basic'):
            pytest.skip('Basic ACL tests were skipped as requested')

    def setup_rules(self, dut, setup, acl_table):
        """
        setup rules on DUT
        :param dut: dut host
        :param setup: setup information
        :param acl_table: acl table creating fixture
        :return:
        """

        name = acl_table['acl_table_name']
        dir = setup['dut_tmp_dir']

        logger.info('Generate config for ACL rule ACL table {table_name}'.format(table_name=name))
        dut.template(src='acl/templates/acltb_test_rules.j2',
                     dest='{dir}/acl_rules_{name}.json'.format(dir=dir,
                                                               name=name)
        )

        dut.command('config acl update full {}/acl_rules_{}.json'.format(dir, name))


class TestIncrementalAcl(BaseAclTest):
    """
    Incremental ACL rules configuration traffic tests.
    Setup rules using incremental update in two parts, run traffic tests cases.
    """

    @pytest.fixture(scope='class', autouse=True)
    def skip(self, request):
        """
        skip test class fixture based on CLI
        :param request: pytest request object
        :return:
        """

        if not request.config.getoption('--acl-incremental'):
            pytest.skip('Incremental ACL configuration tests were skipped as requested')

    def setup_rules(self, dut, setup, acl_table):
        """
        setup rules on DUT for incremental test
        :param dut: dut host
        :param setup: setup information
        :param acl_table: acl table creating fixture
        :return:
        """

        name = acl_table['acl_table_name']
        dir = setup['dut_tmp_dir']

        logger.info('Generate incremental config for ACL rule ACL table {table_name}'.format(table_name=name))
        for i in xrange(2):
            dut.template(src='acl/templates/acltb_test_rules_part_{}.j2'.format(i + 1),
                         dest='{}/acl_rules_{}_part_{}.json'.format(dir, name, i + 1))

        for i in xrange(2):
            dut.command('config acl update incremental {}/acl_rules_{}_part_{}.json'.format(dir, name, i + 1))


@pytest.mark.reboot
class TestAclWithReboot(BaseAclTest):
    """
    Basic ACL rules traffic tests with reboot.
    Verify that the ACL configurations persist after reboot
    """

    @pytest.fixture(scope='class', autouse=True)
    def skip(self, request):
        """
        skip test class fixture based on CLI
        :param request: pytest request object
        :return:
        """

        if not request.config.getoption('--acl-with-reboot'):
            pytest.skip('ACL tests with reboot were skipped as requested')

    def setup_rules(self, dut, setup, acl_table):
        """
        setup rules on DUT
        :param dut: dut host
        :param setup: setup information
        :param acl_table: acl table creating fixture
        :return:
        """

        super(TestAclWithReboot, self).setup_rules(dut, setup, acl_table)
        dut.command('config save -y')
        reboot(dut)

    def teardown_rules(self, dut):
        """
        teardown ACL rules after test by applying empty configuration
        :param dut: DUT host object
        :return:
        """

        super(TestAclWithReboot, self).teardown_rules()
        dut.command('config save -y')
