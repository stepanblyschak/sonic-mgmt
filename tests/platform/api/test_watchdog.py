import os
import time
import config
import yaml
import pytest
from common.helpers.platform_api import watchdog

TEST_CONFIG_FILE = os.path.join(os.path.split(__file__)[0], "watchdog.yml")


@pytest.fixture(scope='function', autouse=True)
def watchdog_not_running(duthost, start_platform_api_service):
    # assert watchdog is not running before test case
    assert not watchdog.is_armed(duthost)

    try:
        yield
    finally:
        # disarm watchdog after test case
        watchdog.disarm(duthost)


@pytest.fixture(scope='function')
def conf(request, duthost):
    class TestConfig:
        def __init__(self, conf):
            self.conf = conf
        def __getitem__(self, key):
            if key not in self.conf or self.conf[key] is None:
                pytest.skip("{} is required".format(key))
            return self.conf[key]

    test_config = None
    with open(TEST_CONFIG_FILE) as stream:
        test_config = yaml.safe_load(stream)

    default_test_config = test_config['default']

    platform = duthost.facts['platform']
    hwsku = duthost.facts['hwsku']

    if platform in test_config and 'default' in test_config[platform]:
        default_test_config.update(test_config[platform]['default'])

    if platform in test_config and hwsku in test_config[platform]:
        default_test_config.update(test_config[platform][hwsku])

    return TestConfig(default_test_config)


class TestWatchdogAPI(object):
    ''' Hardware watchdog platform API test cases '''

    def test_arm_disarm_states(self, testbed_devices, conf):
        ''' arm watchdog with a valid timeout value, verify it is in armed state,
        disarm watchdog and verify it is in disarmed state
        '''

        duthost = testbed_devices['dut']
        localhost = testbed_devices['localhost']

        test_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(duthost, test_timeout)

        assert actual_timeout != -1
        assert actual_timeout >= test_timeout
        assert watchdog.is_armed(duthost)

        assert watchdog.disarm(duthost)
        assert not watchdog.is_armed(duthost)

        res = localhost.wait_for(host=duthost.hostname,
                port=22, state="stopped", delay=5, timeout=test_timeout,
                module_ignore_errors=True)

        assert 'exception' in res

    def test_remaining_time(self, duthost, conf):
        ''' arm watchdog with a valid timeout and verify that remaining time API works correctly '''

        test_timeout = conf['valid_timeout']

        assert watchdog.get_remaining_time(duthost) == -1

        actual_timeout = watchdog.arm(duthost, test_timeout)
        remaining_time = watchdog.get_remaining_time(duthost)

        assert remaining_time > 0
        assert remaining_time <= actual_timeout

        remaining_time = watchdog.get_remaining_time(duthost)
        time.sleep(1)
        assert watchdog.get_remaining_time(duthost) < remaining_time

    def test_periodic_arm(self, duthost, conf):
        ''' arm watchdog several times as watchdog deamon would and verify API behaves correctly '''

        test_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(duthost, test_timeout)
        time.sleep(1)
        remaining_time = watchdog.get_remaining_time(duthost)
        actual_timeout_second = watchdog.arm(duthost, test_timeout)

        assert actual_timeout == actual_timeout_second
        assert watchdog.get_remaining_time(duthost) > remaining_time

    def test_arm_different_timeout_greater(self, duthost, conf):
        ''' arm the watchdog with greater timeout value and verify new timeout was accepted;
        If platform accepts only single valid timeout value, @greater_timeout should be None.
        '''

        test_timeout = conf['valid_timeout']
        test_timeout_second = conf.get('greater_timeout', None)
        if test_timeout_second is None:
            pytest.skip('"greater_timeout" parameter is required for this test case')
        actual_timeout = watchdog.arm(duthost, test_timeout)
        remaining_time = watchdog.get_remaining_time(duthost)
        actual_timeout_second = watchdog.arm(duthost, test_timeout_second)

        assert actual_timeout < actual_timeout_second
        assert watchdog.get_remaining_time(duthost) > remaining_time

    def test_arm_different_timeout_smaller(self, duthost, conf):
        ''' arm the watchdog with smaller timeout value and verify new timeout was accepted;
        If platform accepts only single valid timeout value, @greater_timeout should be None.
        '''

        test_timeout = conf['greater_timeout']
        test_timeout = conf.get('greater_timeout', None)
        if test_timeout is None:
            pytest.skip('"greater_timeout" parameter is required for this test case')
        test_timeout_second = conf['valid_timeout']
        actual_timeout = watchdog.arm(duthost, test_timeout)
        remaining_time = watchdog.get_remaining_time(duthost)
        actual_timeout_second = watchdog.arm(duthost, test_timeout_second)

        assert actual_timeout > actual_timeout_second
        assert watchdog.get_remaining_time(duthost) < remaining_time

    def test_arm_too_big_timeout(self, duthost, conf):
        ''' try to arm the watchdog with timeout that is too big for hardware watchdog;
        If no such limitation exist, @too_big_timeout should be None for such platform.
        '''

        test_timeout = conf.get('too_big_timeout', None)
        if test_timeout is None:
            pytest.skip('"too_big_timeout" parameter is required for this test case')
        actual_timeout = watchdog.arm(duthost, test_timeout)

        assert actual_timeout == -1

    def test_arm_negative_timeout(self, duthost):
        ''' try to arm the watchdog with negative value '''

        test_timeout = -1
        actual_timeout = watchdog.arm(duthost, test_timeout)

        assert actual_timeout == -1

    @pytest.mark.disable_loganalyzer
    def test_reboot(self, testbed_devices, conf):
        ''' arm the watchdog and verify it did its job after timeout expiration '''

        duthost = testbed_devices['dut']
        localhost = testbed_devices['localhost']

        test_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(duthost, test_timeout)

        assert actual_timeout != -1

        res = localhost.wait_for(host=duthost.hostname, port=22, state="stopped", delay=2, timeout=actual_timeout,
                                 module_ignore_errors=True)
        assert 'exception' in res

        res = localhost.wait_for(host=duthost.hostname, port=22, state="started", delay=10, timeout=120,
                                 module_ignore_errors=True)
        assert 'exception' not in res

        # wait for system to startup
        time.sleep(120)

    @pytest.fixture(scope='function', autouse=True)
    def restore_if_rebooted(self, testbed_devices):
        duthost = testbed_devices['dut']
        localhost = testbed_devices['localhost']
        try:
            yield
        finally:
            res = localhost.wait_for(host=duthost.hostname, port=22, state="started", delay=2, timeout=1,
                                    module_ignore_errors=True)
            # if host is unreachable
            if 'exception' in res:
                # wait for dut to come back
                res = localhost.wait_for(host=duthost.hostname, port=22, state="started", delay=10, timeout=120,
                                        module_ignore_errors=True)
                assert 'exception' not in res

                # wait for system to startup
                time.sleep(120)

                raise Exception("DUT was left down (probably watchdog) after test case")
