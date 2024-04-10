from tests.lib.tools import AgentTestCase
from azurelinuxagent.common.policy.policy_engine import PolicyEngine, ExtensionPolicyEngine
from azurelinuxagent.common.policy.policy_engine import ExtensionPolicyEngine
import unittest
from azurelinuxagent.common.policy.policy_engine import ExtensionPolicyEngine
from azurelinuxagent.common.protocol.restapi import ExtensionSettings, Extension, ExtHandlerStatus, \
    ExtensionStatus, ExtensionRequestedState


class TestPolicyEngine(AgentTestCase):
    """Test the PolicyEngine class."""

    policy_file = "/home/manugunnala/agents/WALinuxAgent/tests/common/policy/extension_list/extension_policy.rego"
    data_file = "/home/manugunnala/agents/WALinuxAgent/tests/common/policy/extension_list/extension-data-real.json"
    input_file = "/home/manugunnala/agents/WALinuxAgent/tests/common/policy/extension_list/extension-input.json"
    all_extensions = None

    def setUp(self):
        super(TestPolicyEngine, self).setUp()

        # create mock extension objects
        h1 = Extension("ext1")
        h2 = Extension("ext2")
        h3 = Extension("ext3")
        ext_settings = ExtensionSettings("notreal")
        self.all_extensions = [(ext_settings, h1), (ext_settings, h2), (ext_settings, h3)]

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
        result = policy_engine.eval_query("data.extension_policy", return_json=True)
        print(result)
        assert result["result"][0]["expressions"][0]["value"]["allowed_extensions"] == {}

    def test_create_extension_policy_engine_empty(self):
        """
        Test case to verify the creation of a ExtensionPolicyEngine object with no policy file and data file.
        """
        policy_engine = ExtensionPolicyEngine()
        self.assertIsNotNone(policy_engine)

    def test_create_extension_policy_engine_with_files(self):
        """
        Test case to verify the creation of a ExtensionPolicyEngine object with policy file and data file.
        """
        policy_engine = PolicyEngine(policy_file=self.policy_file, data_file=self.data_file)
        self.assertIsNotNone(policy_engine)

    def test_get_allowed_list_all(self):
        """Test when all extensions are allowed"""
        data_all = """{
                        "allowed": {
                            "all":{}
                        }
                    }
                    """
        policy_engine = ExtensionPolicyEngine(self.policy_file, data_all)
        allowed = policy_engine.get_allowed_list(self.all_extensions)
        assert "ext1" in allowed
        assert "ext2" in allowed
        assert "ext3" in allowed

    def test_get_allowed_list_empty(self):
        """Test when allowlist is empty. All extensions should be denied."""
        data_none = """{
                    "allowed": {
                        }
                    }
                """
        policy_engine = ExtensionPolicyEngine(self.policy_file, data_none)
        allowed = policy_engine.get_allowed_list(self.all_extensions)
        assert allowed == {}
        assert "ext1" not in allowed

    def test_get_allowed_list_name(self):
        """Test to allow one specific extension by name"""
        data = """{
                    "allowed": {
                        "ext1": {
                            "name": "ext1"
                        },
                        "ext4": {
                            "name": "ext4"
                        }
                    }
                }
                """
        policy_engine = ExtensionPolicyEngine(self.policy_file, data)
        allowed = policy_engine.get_allowed_list(self.all_extensions)
        print(allowed)
        assert "ext1" in allowed
        assert "ext4" not in allowed

    def test_get_allowed_list_deny(self):
        """Test to deny one specific extension by name"""
        data = """{
                    "allowed": {
                        "ext1": {
                            "name": "ext1"
                        }, 
                        "ext2": {
                            "name": "ext2"
                        }
                    }
                }
                """
        policy_engine = ExtensionPolicyEngine(self.policy_file, data)
        allowed = policy_engine.get_allowed_list(self.all_extensions)
        assert "ext3" not in allowed
