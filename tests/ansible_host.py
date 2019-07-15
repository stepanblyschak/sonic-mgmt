import json

class ModuleException(Exception):
    @property
    def module_name(self):
        return self._module_name

    @property
    def module_result(self):
        return self._module_result

    def __init__(self, module_name, module_result):
        self._module_name = module_name
        self._module_result = module_result
        pretty_json = json.dumps(self._module_result, indent=4, sort_keys=True)
        msg = "run module {} failed, ansible result:\n{}".format(self._module_name, pretty_json)
        super(ModuleException, self).__init__(msg)

class ansible_host():

    def __init__(self, ansible_adhoc, hostname, is_local=False):
        self.fails = False
        if is_local:
            self.host = ansible_adhoc(inventory='localhost', connection='local')[hostname]
        else:
            self.host = ansible_adhoc(become=True)[hostname]
        self.hostname = hostname

    def __getattr__(self, item):
        self.module_name = item
        self.module = getattr(self.host, item)
 
        return self._run

    def _run(self, *module_args, **complex_args):
   
        res = self.module(*module_args, **complex_args)[self.hostname]
        if res.is_failed:
            raise ModuleException(self.module_name, res)

        return res

