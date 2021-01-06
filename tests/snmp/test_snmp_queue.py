import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_snmp_queues(duthosts, rand_one_dut_hostname, localhost, creds, collect_techsupport):
    duthost = duthosts[rand_one_dut_hostname]

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    for k, v in snmp_facts['snmp_interfaces'].items():
        description = v.get('description', '')
        is_fp_port = 'Ethernet' in description
        if is_fp_port:
            if not v.has_key('queues'):
                pytest.fail("port %s does not have queue counters" % v['name'])
