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
from azurelinuxagent.common.utils.textutil import parse_doc, parse_json, findall, find, findtext, getattrib, gettext, format_exception, \
    is_str_none_or_whitespace, is_str_empty
from azurelinuxagent.common.protocol.restapi import Extension
from azurelinuxagent.common.protocol.extensions_goal_state_from_extensions_config import ExtensionsGoalStateFromExtensionsConfig

class PolicyEngine():

    def __init__(self):
        self._engine = None

        try:
            self._engine = regorus.Engine()
        except Exception as e:
            raise Exception("Error creating policy engine: " + str(e))

    def add_policy(self, policy_file):
        try:
            self._engine.add_policy_from_file(policy_file)
        except Exception as e:
            raise Exception("Error adding policy from file: " + str(e))

    def add_data_from_file(self, data_file):
        # expects the input file to be a json
        try:
            data = json.load(open(data_file))
            self._engine.add_data(data)
        except Exception as e:
            raise Exception("Error adding data: " + str(e))
      
    def add_data_from_json(self, data_json):
        try:
            self._engine.add_data_json(data_json)
        except Exception as e:
            raise Exception("Error adding data: " + str(e))

    def set_input_from_file(self, input_file):
      # this method expects the input file to be a json
        try:
            input = json.load(open(input_file))
            self._engine.set_input(input)
        except Exception as e:
            raise Exception("Error setting input: " + str(e))

    def set_input_from_json(self, input_json):
        try:
            self._engine.set_input_json(input_json)
        except Exception as e:
            raise Exception("Error setting input: " + str(e))

    def eval_query(self, query, return_json=True):
        try:
            if return_json:
                results = self._engine.eval_query_as_json(query)
            else:
                results = self._engine.eval_query(query)
            return results
        except Exception as e:
            raise Exception("Error evaluating query: " + str(e))

    def get_allowed_list(self, output_json):
        output = json.loads(output_json)
        return output["result"][0]["expressions"][0]["value"]["allowed_extensions"]

    def get_denied_list(self, output_json):
        output = json.loads(output_json)
        return output["result"][0]["expressions"][0]["value"]["denied_extensions"]

    def convert_list_to_json(self, list):
      # TO DO - update this method so we're capturing all of the attributes/settings in the list objects
      ext_dict = {ext[0]: {"version": ext[1].split('-')[1]} for ext in list}

      # Wrap in 'incoming' object
      json_obj = {'incoming': ext_dict}

      # Convert to JSON string
      json_str = json.dumps(json_obj, indent=4)
      return json_str

    # TO DO
    def check_for_wheel_file():
        return True


# for testing
def test1():

    policy_path = "./extension_list/extension_policy.rego"
    # data_path = "./extension_list/extension-data-empty2.json"
    data_path = "./extension_list/extension-data.json"
    # data_path = "./extension_list/extension-data-all.json"
    input_path = "./extension_list/extension-input-newVersion.json"

    # Create engine
    engine = PolicyEngine()
    engine.add_policy(policy_path)
    engine.add_data_from_file(data_path)
    engine.set_input_from_file(input_path)

    res = engine.eval_query('data.extension_policy')
    allowed = engine.get_allowed_list(res)
    allowed_names = list(allowed.keys())
    print("Allowed extensions: " + str(allowed))

    denied = engine.get_denied_list(res)
    denied_names = list(denied.keys())
    print("Denied extensions: " + str(denied))
    pass
  
  

def test2():

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

def test3():
    # log time
    start_time = time.time()

    # set up policy engine
    policy_path = "./extension_list/extension_policy.rego"
    data_path = "./extension_list/demo-data.json" # specify allowed extensions
    # data_path = "./extension_list/extension-data-all2.json" # allow all
    # data_path = "./extension_list/extension-data-empty2.json" # deny all
    engine = PolicyEngine()
    engine.add_policy(policy_path)
    engine.add_data_from_file(data_path)

    # define input
    # all_extensions comes from agent exthandler after processing goal state
    # list elements are tuples of (ExtensionSettings, Extension)
    all_extensions = [("Microsoft.CPlat.Core.LinuxPatchExtension", "Microsoft.CPlat.Core.LinuxPatchExtension-1.6.49"), \
            ("Microsoft.Azure.Monitor.AzureMonitorLinuxAgent", "Microsoft.Azure.Monitor.AzureMonitorLinuxAgent-1.29.4"), \
            ("Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent", "Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent-2.24.325"), \
            ("Microsoft.CPlat.Core.RunCommandLinux", "Microsoft.CPlat.Core.RunCommandLinux-1.0.5")]

    # convert and set input
    print("-----------------Policy engine input----------------")
    print(all_extensions)
    converted_input = engine.convert_list_to_json(all_extensions)
    engine.set_input_from_json(converted_input)

    # run policy and get allowed/denied lists
    res = engine.eval_query('data.extension_policy')
    allowed = engine.get_allowed_list(res)
    denied = engine.get_denied_list(res)

    # print results
    print("\n-----------------Policy engine output---------------")
    allowed_names = list(allowed.keys())
    print("Allowed extensions: " + str(allowed_names))
    denied_names = list(denied.keys())
    print("Denied extensions: " + str(denied_names))

    # # log time taken
    # end_time = time.time()
    # elapsed_time_ms = round(1000 * (end_time - start_time), 5)
    # print("\nTime taken: " + str(elapsed_time_ms) + " ms")

    # example of how we'd process this in agent code
    print("\n-----------------Guest agent logs-------------------")
    for e1, e2 in all_extensions:
        if e1 in allowed_names:
            print("Installing " + e1)
        elif e1 in denied_names:
            print("Extension " + e1 + " is blocked by policy. Skipping installation.")


if __name__ == "__main__":
    # test1()
    # test2()
    test3()
