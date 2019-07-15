import pytest
from ansible_host import ansible_host


def pytest_addoption(parser):
    parser.addoption(
        '--acl-ingress',
        action='store_true',
        default=True,
        help='Run only ACL ingress tests',
    )
    parser.addoption(
        '--acl-egress',
        action='store_true',
        default=False,
        help='Run only ACL egress tests',
    )
    parser.addoption(
        '--acl-basic',
        action='store_true',
        default=True,
        help='Run only ACL basic traffic test',
    )
    parser.addoption(
        '--acl-incremental',
        action='store_true',
        default=True,
        help='Run only ACL incremental configuration and traffic test',
    )
    parser.addoption(
        '--acl-with-reboot',
        action='store_true',
        default=False,
        help='Run only ACL traffic tests with reboot',
    )
    parser.addoption(
        '--acl-with-port-toggle',
        action='store_true',
        default=False,
        help='Run only ACL traffic tests with port toggling',
    )


#### THESE FIXTURES BELOW A CANDIDATES TO REMOVE ####

@pytest.fixture(scope='session')
def dut(request, testbed):
    duthostname = testbed['dut']
    plugin = request.config.pluginmanager.getplugin("ansible")

    def init_host_mgr(**kwargs):
        return plugin.initialize(request.config, request, **kwargs)
    return ansible_host(init_host_mgr, duthostname)

@pytest.fixture(scope='session')
def ptfhost(request, testbed):
    ptfhostname = 'ptf-1025' # FIXME: testbed['ptf']
    plugin = request.config.pluginmanager.getplugin("ansible")

    def init_host_mgr(**kwargs):
        return plugin.initialize(request.config, request, **kwargs)

    hostobj = ansible_host(init_host_mgr, ptfhostname)

    # additionally deploy ptf tests
    hostobj.copy(src='ptftests', dest='~/')
    hostobj.copy(src='acstests', dest='~/')

    return hostobj

