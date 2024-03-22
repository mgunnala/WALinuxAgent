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
import time
import json
import sys
import os
from azurelinuxagent.common import logger
from azurelinuxagent.common.utils.textutil import parse_doc, parse_json, findall, find, findtext, getattrib, gettext, format_exception, \
    is_str_none_or_whitespace, is_str_empty
from azurelinuxagent.common.protocol.restapi import Extension, ExtHandlerStatus, ExtensionSettings
from azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config import ExtensionsGoalStateFromExtensionsConfig

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

    def __str__(self):
        return "My engine"

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
        self.set_input_from_json(self.convert_list_to_json(ext_list))

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

        return input_json


# for testing
def test1():

    # set up engine
    policy_path = "./extension_list/extension_policy.rego"
    data_path = "./extension_list/extension-data.json"
    input_path = "./extension_list/extension-input-newVersion.json"
    engine = PolicyEngine()
    engine.add_policy(policy_path)
    engine.add_data(data_path)
    engine.set_input(input_path)

    sample_xml = \
        """
        <RootElement>
        <Plugins>
          <Plugin name="Microsoft.CPlat.Core.NullSeqB" version="2.0.1" location="https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqB_useast2euap_manifest.xml" state="enabled" autoUpgrade="false" failoverlocation="https://zrdfepirv2cbz06prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqB_useast2euap_manifest.xml" runAsStartupTask="false" isJson="true" useExactVersion="true" />
          <Plugin name="Microsoft.CPlat.Core.NullSeqA" version="2.0.1" location="https://zrdfepirv2cbn04prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqA_useast2euap_manifest.xml" state="enabled" autoUpgrade="false" failoverlocation="https://zrdfepirv2cbn06prdstr01a.blob.core.windows.net/f72653efd9e349ed9842c8b99e4c1712/Microsoft.CPlat.Core_NullSeqA_useast2euap_manifest.xml" runAsStartupTask="false" isJson="true" useExactVersion="true" />
        </Plugins>
        <PluginSettings>
          <Plugin name="Microsoft.CPlat.Core.NullSeqA" version="2.0.1">
            <DependsOn dependencyLevel="1">
              <DependsOnExtension handler="Microsoft.CPlat.Core.NullSeqB" />
            </DependsOn>
            <RuntimeSettings seqNo="0">{
              "runtimeSettings": [
                {
                  "handlerSettings": {
                    "publicSettings": {"01_add_extensions_with_dependency":"ff2a3da6-8e12-4ab6-a4ca-4e3a473ab385"}
                  }
                }
              ]
            }
            </RuntimeSettings>
          </Plugin>
          <Plugin name="Microsoft.CPlat.Core.NullSeqB" version="2.0.1">
            <RuntimeSettings seqNo="0">{
              "runtimeSettings": [
                {
                  "handlerSettings": {
                    "publicSettings": {"01_add_extensions_with_dependency":"2e837740-cf7e-4528-b3a4-241002618f05"}
                  }
                }
              ]
            }
            </RuntimeSettings>
          </Plugin>
        </PluginSettings>
        </RootElement>"""

    xml_doc = parse_doc(sample_xml)
    plugins_list = find(xml_doc, "Plugins")
    plugins = findall(plugins_list, "Plugin")
    plugin_settings_list = find(xml_doc, "PluginSettings")
    plugin_settings = findall(plugin_settings_list, "Plugin")


    all_extensions = []
    for plugin in plugins:
        extension = Extension()

        ExtensionsGoalStateFromExtensionsConfig._parse_plugin(extension, plugin)
        ExtensionsGoalStateFromExtensionsConfig._parse_plugin_settings(extension, plugin_settings)

        # build a list of all extensions from crp
        all_extensions.append(extension)
  
    # all_extensions is now input
    print(all_extensions)
    
    # we want to convert it into a json input

def demo(scenario):
    # log time
    start_time = time.time()

    # set up policy engine
    policy_path = "./extension_list/extension_policy.rego"
    if scenario == "allow_all":
        data_path = "./extension_list/extension-data-all2.json"
    elif scenario == "deny_all":
        data_path = "./extension_list/extension-data-empty2.json"
    else:
        data_path = "./extension_list/demo-data.json"
    engine = ExtensionPolicyEngine(policy_path, data_path)

    # define input
    # all_extensions comes from agent exthandler after processing goal state
    # list elements are tuples of (ExtensionSettings, Extension)
    all_extensions = [("Microsoft.CPlat.Core.LinuxPatchExtension", "Microsoft.CPlat.Core.LinuxPatchExtension-1.6.4"), \
            ("Microsoft.Azure.Monitor.AzureMonitorLinuxAgent", "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.29.4"), \
            ("Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent", "Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent-2.24.325"), \
            ("Microsoft.CPlat.Core.RunCommandLinux", "Microsoft.CPlat.Core.RunCommandLinux-1.0.5")]

    # convert and set input
    print("-----------------Policy engine input----------------")
    print(all_extensions)
    converted_input = engine.convert_list_to_json(all_extensions)
    print(converted_input)
    engine.set_input_from_json(converted_input)

    # run policy and get allowed/denied lists
    res = engine.eval_query('data.extension_policy')
    engine.set_allowed_list(res)
    engine.set_denied_list(res)
    print("\n-----------------Policy engine output---------------")
    print("Allowed extensions: " + str(engine.allowed_list))
    print("Denied extensions: " + str(engine.denied_list))

    # # log time taken
    # end_time = time.time()
    # elapsed_time_ms = round(1000 * (end_time - start_time), 5)
    # print("\nTime taken: " + str(elapsed_time_ms) + " ms")

    # example of how we'd process this in agent code
    print("\n-----------------Guest agent logs-------------------")
    for e1, e2 in all_extensions:
        if e1 in engine.allowed_list.keys():
            print("Installing " + e1)
        elif e1 in engine.denied_list.keys():
            print("Extension " + e1 + " is disabled by policy and will not be processed. Creating status file.")


if __name__ == "__main__":
    # test1()
    if len(sys.argv) < 2:
        scenario = "allow_all"
    else:
      scenario = sys.argv[1]
    demo(scenario)
