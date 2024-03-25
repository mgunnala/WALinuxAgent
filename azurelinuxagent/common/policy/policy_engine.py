# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import regorus
import json
from azurelinuxagent.common import logger
from azurelinuxagent.common.protocol.restapi import Extension, ExtHandlerStatus, ExtensionSettings

class PolicyEngine:
    """Base class for policy engine"""
    def __init__(self, policy_file=None, data_file=None):
        self._engine = regorus.Engine()
        if policy_file is not None:
            self._engine.add_policy_from_file(policy_file)
        if data_file is not None:
            with open(data_file, 'r') as f:
                data = json.load(f)
            self._engine.add_data(data)

    def add_policy(self, policy_file):
        """Add policy from file"""
        self._engine.add_policy_from_file(policy_file)

    def add_data_from_file(self, data_file):
        """Add data from file"""
        # expects the input file to be a json
        data = json.load(open(data_file))
        self._engine.add_data(data)

    def add_data_from_json(self, data_json):
        """Add data from json"""
        self._engine.add_data_json(data_json)

    def set_input_from_file(self, input_file):
        """Set input from file"""
        # this method expects the input file to be a json
        input = json.load(open(input_file))
        self._engine.set_input(input)

    def set_input_from_json(self, input_json):
        """Set input from json"""
        self._engine.set_input_json(input_json)

    def eval_query(self, query, return_json=True):
        """Evaluate query"""
        if return_json:
            results = self._engine.eval_query_as_json(query)
        else:
            results = self._engine.eval_query(query)
        return results


class ExtensionPolicyEngine(PolicyEngine):
    """Implement the policy engine for extension allow/disallow policy"""
    policy_path = None
    data_path = None
    all_extensions = []
    allowed_list = None
    denied_list = None

    def __init__(self, policy_path=None, data_path=None):
        self.policy_path = policy_path
        self.data_path = data_path
        super().__init__(self.policy_path, self.data_path)

    def set_allowed_list(self, output_json):
        output = json.loads(output_json)
        self.allowed_list = output["result"][0]["expressions"][0]["value"]["allowed_extensions"]

    def set_denied_list(self, output_json):
        output = json.loads(output_json)
        self.denied_list = output["result"][0]["expressions"][0]["value"]["denied_extensions"]

    def set_input_from_list(self, ext_list):
        self.all_extensions = ext_list
        converted_list = self.convert_list_to_json(self.all_extensions)
        self.set_input_from_json(converted_list)

    def convert_list_to_json(self, ext_list):
        input_json = {
          "incoming": {}
        }
        for setting, ext in ext_list:
            template = {
                "name": None
                # "version": None,
                # "state": None,
                # "settings": None,
                # "manifest_uris": None,
                # "supports_multi_config": None,
                # "is_invalid_setting": None,
                # "invalid_setting_reason": None
            }
            template["name"] = ext.name
            # template["version"] = ext.version
            # template["state"] = ext.state
            # template["settings"] = setting
            # template["manifest_uris"] = ext.manifest_uris
            # template["supports_multi_config"] = ext.supports_multi_config
            # template["is_invalid_setting"] = ext.is_invalid_setting
            # template["invalid_setting_reason"] = ext.invalid_setting_reason
            input_json["incoming"][ext.name] = template

        return json.dumps(input_json)
