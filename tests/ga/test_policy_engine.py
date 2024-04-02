from tests.lib.tools import AgentTestCase, patch, load_data
from azurelinuxagent.common.policy.policy_engine import PolicyEngine, ExtensionPolicyEngine

class TestPolicyEngine(AgentTestCase):
    
    policy_file = "/home/manugunnala/agents/WALinuxAgent/azurelinuxagent/common/policy/extension_list/extension_policy.rego"
    data_file = "/home/manugunnala/agents/WALinuxAgent/azurelinuxagent/common/policy/extension_list/extension-data-real.json"
    input_file = "/home/manugunnala/agents/WALinuxAgent/azurelinuxagent/common/policy/extension_list/extension-input.json"
        
    def setUp(self):
        super(TestPolicyEngine, self).setUp()

    def test_create_policy_engine_empty(self):
        """
        Test case to verify the creation of a PolicyEngine object with no policy file and data file.
        """
        policy_engine = PolicyEngine()
        self.assertIsNotNone(policy_engine)

    def test_create_policy_engine_with_files(self):
        """
        Test case to verify the creation of a PolicyEngine object with policy file and data file.
        """
        policy_engine = PolicyEngine(policy_file=self.policy_file, data_file=self.data_file)
        self.assertIsNotNone(policy_engine)

    def test_policy_engine_add_policy(self):
        """
        Test case to verify the addition of a policy file to the PolicyEngine object.
        """
        policy_engine = PolicyEngine()
        policy_engine.add_policy(self.policy_file)
        
    def test_policy_engine_add_data_file(self):
        """
        Test case to verify the addition of a data file to the PolicyEngine object.
        """
        policy_engine = PolicyEngine()
        policy_engine.add_data(self.data_file)
     
    def test_policy_engine_add_data_json(self):
        """
        Test case to verify the addition of data in JSON format to the PolicyEngine object.
        """
        test_data = """
        {
            "allowed": {
                "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux": {
                    "name": "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
                },
                "Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent": {
                    "name": "Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent"
                },
                "Microsoft.OSTCExtensions.VMAccessForLinux": {
                    "name": "Microsoft.OSTCExtensions.VMAccessForLinux"
                }
            }
        }
        """
        policy_engine = PolicyEngine()
        policy_engine.add_data(test_data)

    def test_policy_engine_set_input_from_file(self):
        """
        Test case to verify the setting of input from a file in the PolicyEngine object.
        """
        policy_engine = PolicyEngine()
        policy_engine.set_input(self.input_file)

    def test_policy_engine_set_input_from_json(self):
        """
        Test case to verify the setting of input from JSON in the PolicyEngine object.
        """
        test_input = """
        {
            "incoming": {
                "ext1": {
                    "urls": ["url1", "url2"],
                    "state": "enabled",
                    "settings":["setting1", "setting2"],
                    "version": "1.0"
                },
                "ext2": {
                    "location": "url2",
                    "state": "disabled",
                    "version": "2.0"
                },
                "ext3": {
                    "location": "url3",
                    "state": "enabled",
                    "version": "1.0"
                }
            }
        }
        """
        policy_engine = PolicyEngine()
        policy_engine.set_input(test_input)

    def test_policy_engine_eval_query(self):
        policy_engine = PolicyEngine(self.policy_file, self.data_file)
        policy_engine.set_input(self.input_file)
        result = policy_engine.eval_query("data.extension_policy")
        
        
        print(result)
        assert result == True

    # def test_extension_policy_engine_init(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     self.assertIsNotNone(extension_policy_engine)

    # def test_extension_policy_engine_set_allowed_list(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     extension_policy_engine.set_allowed_list({"key": "value"})
    #     # Add assertions to check if the allowed list was set successfully

    # def test_extension_policy_engine_set_denied_list(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     extension_policy_engine.set_denied_list({"key": "value"})
    #     # Add assertions to check if the denied list was set successfully

    # def test_extension_policy_engine_set_input_from_list(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     extension_policy_engine.set_input_from_list(["extension1", "extension2"])
    #     # Add assertions to check if the input list was set successfully

    # def test_extension_policy_engine_convert_list_to_json(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     extension_policy_engine.convert_list_to_json(["extension1", "extension2"])
    #     # Add assertions to check if the list was converted to JSON successfully
    
    def setUp(self):
        super(TestPolicyEngine, self).setUp()
        self.policy_file = "/home/manugunnala/agents/WALinuxAgent/azurelinuxagent/common/policy/extension_list/extension_policy.rego"
        self.data_file = "/home/manugunnala/agents/WALinuxAgent/azurelinuxagent/common/policy/extension_list/extension-data-real.json"

    def test_create_policy_engine_empty(self):
        policy_engine = PolicyEngine()
        self.assertIsNotNone(policy_engine)

    def test_create_policy_engine_with_files(self):
        policy_engine = PolicyEngine(policy_file=self.policy_file, data_file=self.data_file)
        self.assertIsNotNone(policy_engine)

    def test_policy_engine_add_policy(self):
        policy_engine = PolicyEngine()
        policy_engine.add_policy(self.policy_file)
        
    def test_policy_engine_add_data_file(self):
        policy_engine = PolicyEngine()
        policy_engine.add_data(self.data_file)
     
    def test_policy_engine_add_data_json(self):
        test_data = """
        {
            "allowed": {
                "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux": {
                    "name": "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"
                },
                "Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent": {
                    "name": "Microsoft.Azure.Security.Monitoring.AzureSecurityLinuxAgent"
                },
                "Microsoft.OSTCExtensions.VMAccessForLinux": {
                    "name": "Microsoft.OSTCExtensions.VMAccessForLinux"
                }
            }
        }
        """
        policy_engine = PolicyEngine()
        policy_engine.add_data(test_data)

    def test_policy_engine_set_input_from_file(self):
        policy_engine = PolicyEngine()
        policy_engine.set_input(self.data_file)

    def test_policy_engine_set_input_from_json(self):
        test_input = """
        {
            "incoming": {
                "ext1": {
                    "urls": ["url1", "url2"],
                    "state": "enabled",
                    "settings":["setting1", "setting2"],
                    "version": "1.0"
                },
                "ext2": {
                    "location": "url2",
                    "state": "disabled",
                    "version": "2.0"
                },
                "ext3": {
                    "location": "url3",
                    "state": "enabled",
                    "version": "1.0"
                }
            }
        }
        """
        policy_engine = PolicyEngine()
        policy_engine.set_input(test_input)

    # def test_policy_engine_eval_query(self):
    #     policy_engine = PolicyEngine()
    #     result = policy_engine.eval_query("query")
    #     # Add assertions to check the result of the query evaluation

    # def test_extension_policy_engine_init(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     self.assertIsNotNone(extension_policy_engine)

    # def test_extension_policy_engine_set_allowed_list(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     extension_policy_engine.set_allowed_list({"key": "value"})
    #     # Add assertions to check if the allowed list was set successfully

    # def test_extension_policy_engine_set_denied_list(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     extension_policy_engine.set_denied_list({"key": "value"})
    #     # Add assertions to check if the denied list was set successfully

    # def test_extension_policy_engine_set_input_from_list(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     extension_policy_engine.set_input_from_list(["extension1", "extension2"])
    #     # Add assertions to check if the input list was set successfully

    # def test_extension_policy_engine_convert_list_to_json(self):
    #     extension_policy_engine = ExtensionPolicyEngine()
    #     result = extension_policy_engine.convert_list_to_json(["extension1", "extension2"])
    #     # Add assertions to check the result of the conversion
