# Copyright 2018 Microsoft Corporation
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
#
# Requires Python 2.4+ and Openssl 1.0+
#

import json
import os
import shutil
import tempfile

from azurelinuxagent.common.protocol.restapi import Extension
from azurelinuxagent.ga.policy.policy_engine import PolicyEngine, ExtensionPolicyEngine, POLICY_SUPPORTED_DISTROS_MIN_VERSIONS, PolicyError
from tests.lib.tools import AgentTestCase, patch, data_dir, test_dir

TEST_EXT_NAME = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"


class TestPolicyEngine(AgentTestCase):
    regorus_dest_path = None    # Location where real regorus executable should be.
    default_policy_path = os.path.join(data_dir, 'policy', "agent-extension-default-data.json")
    default_rule_path = os.path.join(data_dir, 'policy', "agent_extension_policy.rego")
    input_json = None  # Input is stored in a file, and extracted into this variable during class setup.

    @classmethod
    def setUpClass(cls):

        # On a production VM, Regorus will be located in the agent package. Unit tests
        # run within the agent directory, so we copy the executable to ga/policy/regorus and patch path.
        # Note: Regorus has not been published officially, so for now, unofficial exe is stored in tests/data/policy.
        regorus_source_path = os.path.abspath(os.path.join(data_dir, "policy/regorus"))
        cls.regorus_dest_path = os.path.abspath(os.path.join(test_dir, "..", "azurelinuxagent/ga/policy/regorus"))
        if not os.path.exists(cls.regorus_dest_path):
            shutil.copy(regorus_source_path, cls.regorus_dest_path)

        # We store input in a centralized file, we want to extract the JSON contents into a dict for testing.
        # TODO: remove this logic once we add tests for ExtensionPolicyEngine
        with open(os.path.join(data_dir, 'policy', "agent-extension-input.json"), 'r') as input_file:
            cls.input_json = json.load(input_file)
        AgentTestCase.setUpClass()

    @classmethod
    def tearDownClass(cls):
        # Clean up the Regorus binary that was copied to ga/policy/regorus.
        if os.path.exists(cls.regorus_dest_path):
            os.remove(cls.regorus_dest_path)
        AgentTestCase.tearDownClass()

    def test_policy_should_be_enabled_on_supported_distro(self):
        """Policy should be enabled on all supported distros."""
        for distro_name, version in POLICY_SUPPORTED_DISTROS_MIN_VERSIONS.items():
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new=distro_name):
                with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new=version):
                    with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                        engine = PolicyEngine(self.default_rule_path, self.default_policy_path)
                        self.assertTrue(engine.is_policy_enforcement_enabled(), "Policy should be enabled on supported distro {0} {1}".format(distro_name, version))

    def test_should_raise_exception_on_unsupported_distro(self):
        """Policy should NOT be enabled on unsupported distros."""
        test_matrix = {
            "rhel": "9.0",
            "mariner": "1"
        }
        for distro_name, version in test_matrix.items():
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new=distro_name):
                with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new=version):
                    with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                        with self.assertRaises(Exception,
                                           msg="Policy should not be enabled on unsupported distro {0} {1}".format(distro_name, version)):
                            PolicyEngine(self.default_rule_path, self.default_policy_path)

    def test_should_raise_exception_on_unsupported_architecture(self):
        """Policy should NOT be enabled on ARM64."""
        # TODO: remove this test when support for ARM64 is added.
        with patch('azurelinuxagent.ga.policy.policy_engine.get_osutil') as mock_get_osutil:
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                with self.assertRaises(PolicyError, msg="Policy should not be enabled on unsupported architecture ARM64, should have raised exception."):
                    mock_get_osutil.get_vm_arch.return_value = "arm64"
                    PolicyEngine(self.default_rule_path, self.default_policy_path)

    def test_policy_engine_should_evaluate_query(self):
        """
        Should be able to initialize policy engine and evaluate query without an error.
        """
        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                    engine = PolicyEngine(self.default_rule_path, self.default_policy_path)
                    query = "data.agent_extension_policy.extensions_to_download"
                    result = engine.evaluate_query(self.input_json, query)
                    self.assertIsNotNone(result.get(TEST_EXT_NAME), msg="Query should not have returned empty dict.")
                    self.assertTrue(result.get(TEST_EXT_NAME).get('downloadAllowed'),
                                    msg="Query should have returned that extension is allowed.")

    def test_eval_query_should_throw_error_when_disabled(self):
        """
        When policy enforcement is disabled, evaluate_query should throw an error.
        """
        engine = PolicyEngine(self.default_rule_path, self.default_policy_path)
        with self.assertRaises(PolicyError, msg="Should throw error when policy enforcement is disabled."):
            engine.evaluate_query(self.input_json, "data")

    def test_should_throw_error_with_invalid_rule_file(self):
        """
        Evaluate query with invalid rule file, should throw error.
        """
        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                    with self.assertRaises(PolicyError, msg="Should throw error when input is incorrectly formatted."):
                        # pass policy file instead of rule file in init
                        invalid_rule = os.path.join(data_dir, 'policy', "agent_extension_policy_invalid.rego")
                        engine = PolicyEngine(invalid_rule, self.default_policy_path)
                        engine.evaluate_query(self.input_json, "data")

    def test_should_throw_error_with_invalid_policy_file(self):
        """
        Evaluate query with invalid policy file, should throw error.
        """
        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                    with self.assertRaises(PolicyError, msg="Should throw error when policy file is incorrectly formatted."):
                        invalid_policy = os.path.join(data_dir, 'policy', "agent-extension-data-invalid.json")
                        engine = PolicyEngine(self.default_rule_path, invalid_policy)
                        engine.evaluate_query(self.input_json, "data")

    def test_extension_should_be_allowed_if_policy_disabled(self):

        test_ext_handler = Extension(name=TEST_EXT_NAME)
        # Test all combinations of allowlist_rule and signing_rule
        test_cases = [
            {'allowlist_rule': True, 'signing_rule': True},
            {'allowlist_rule': True, 'signing_rule': False},
            {'allowlist_rule': False, 'signing_rule': True},
            {'allowlist_rule': False, 'signing_rule': False}
        ]
        for case in test_cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": case['signing_rule']
                    },
                    "allowListOnly": case['allowlist_rule']
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                with patch('azurelinuxagent.ga.policy.policy_engine.ExtensionPolicyEngine.get_policy_file',
                           return_value=policy_file.name):
                    with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
                        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                            engine = ExtensionPolicyEngine(test_ext_handler)
                            download_allowed = engine.is_extension_download_allowed()
                            self.assertTrue(download_allowed)

    def test_signed_extension_should_be_allowed_if_in_allowlist(self):
        """
        If extension is in allowlist and signed, it should be allowed, regardless of rules.
        """
        test_ext_handler = Extension(name=TEST_EXT_NAME)
        test_ext_handler.encoded_signature = "testsignature123"
        cases = [
            {'allowlist_rule': True, 'global_signing_rule': True, 'individual_signing_rule': True},
            {'allowlist_rule': True, 'global_signing_rule': True, 'individual_signing_rule': False},
            {'allowlist_rule': True, 'global_signing_rule': False, 'individual_signing_rule': True},
            {'allowlist_rule': True, 'global_signing_rule': False, 'individual_signing_rule': False},
            {'allowlist_rule': False, 'global_signing_rule': True, 'individual_signing_rule': True},
            {'allowlist_rule': False, 'global_signing_rule': True, 'individual_signing_rule': False},
            {'allowlist_rule': False, 'global_signing_rule': False, 'individual_signing_rule': True},
            {'allowlist_rule': False, 'global_signing_rule': False, 'individual_signing_rule': False},
        ]
        for case in cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": case['global_signing_rule']
                    },
                    "allowListOnly": case['allowlist_rule']
                },
                "azureGuestExtensionsPolicy": {
                    TEST_EXT_NAME: {
                        "signingRules": {
                            "extensionSigned": case['individual_signing_rule']
                        }
                    }
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                with patch('azurelinuxagent.ga.policy.policy_engine.ExtensionPolicyEngine.get_policy_file',
                           return_value=policy_file.name):
                    with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
                        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                       return_value=True):
                                engine = ExtensionPolicyEngine(test_ext_handler)
                                download_allowed = engine.is_extension_download_allowed()
                                self.assertTrue(download_allowed)

    def test_signed_extension_should_be_allowed_if_allowlist_rule_false(self):
        """
        If global allowlist rule is false, extension should be allowed as long as it is signed.
        """
        test_ext_handler = Extension(name=TEST_EXT_NAME)
        test_ext_handler.encoded_signature = "testsignature123"
        test_cases = [
            {'signing_rule': True},
            {'signing_rule': False}
        ]
        for case in test_cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": case['signing_rule']
                    },
                    "allowListOnly": False
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                with patch('azurelinuxagent.ga.policy.policy_engine.ExtensionPolicyEngine.get_policy_file',
                           return_value=policy_file.name):
                    with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
                        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                       return_value=True):
                                engine = ExtensionPolicyEngine(test_ext_handler)
                                download_allowed = engine.is_extension_download_allowed()
                                self.assertTrue(download_allowed, msg="Allowlist is not enforced, so download should be allowed.")

    def test_should_raise_exception_if_allowlist_rule_true_and_extension_not_in_list(self):
        """
        If global allowlist rule is true and extension not in allowlist, should raise PolicyError.
        """
        test_ext_handler = Extension(name=TEST_EXT_NAME)
        test_ext_handler.encoded_signature = "testsignature123"
        test_cases = [
            {'signing_rule': True},
            {'signing_rule': False}
        ]
        for case in test_cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": case['signing_rule']
                    },
                    "allowListOnly": True
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                with patch('azurelinuxagent.ga.policy.policy_engine.ExtensionPolicyEngine.get_policy_file',
                           return_value=policy_file.name):
                    with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
                        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                       return_value=True):
                                engine = ExtensionPolicyEngine(test_ext_handler)
                                with self.assertRaises(PolicyError, msg="Allowlist is enforced, so download should not be allowed."):
                                    engine.is_extension_download_allowed()

    def test_unsigned_extension_should_raise_exception_if_individual_signing_rule_true(self):
        """
        If extension is not signed and individual signing rule is true, should raise PolicyError.
        """
        test_ext_handler = Extension(name=TEST_EXT_NAME)    # We don't set the signature field, so extension is unsigned.
        test_cases = [
            {'allowlist_rule': True, 'global_signing_rule': True},
            {'allowlist_rule': True, 'global_signing_rule': False},
            {'allowlist_rule': False, 'global_signing_rule': True},
            {'allowlist_rule': False, 'global_signing_rule': False}
        ]
        for case in test_cases:
            policy = {
                    "azureGuestAgentPolicy": {
                        "signingRules": {
                            "extensionSigned": case['global_signing_rule']
                        },
                        "allowListOnly": case['allowlist_rule']
                    },
                    "azureGuestExtensionsPolicy": {
                        TEST_EXT_NAME: {
                            "signingRules": {
                                "extensionSigned": True
                            }
                        }
                    }
                }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                with patch('azurelinuxagent.ga.policy.policy_engine.ExtensionPolicyEngine.get_policy_file',
                           return_value=policy_file.name):
                    with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
                        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                       return_value=True):
                                engine = ExtensionPolicyEngine(test_ext_handler)
                                with self.assertRaises(PolicyError, msg="Extension is not signed and individual signing rule is true, "
                                                       "so download should not be allowed."):
                                    engine.is_extension_download_allowed()

    def test_unsigned_extension_should_be_allowed_if_individual_signing_rule_false(self):
        test_ext_handler = Extension(name=TEST_EXT_NAME)  # We don't set the signature field, so extension is unsigned.
        test_cases = [
            {'allowlist_rule': True, 'global_signing_rule': True},
            {'allowlist_rule': True, 'global_signing_rule': False},
            {'allowlist_rule': False, 'global_signing_rule': True},
            {'allowlist_rule': False, 'global_signing_rule': False}
        ]
        for case in test_cases:
            policy = {
                "azureGuestAgentPolicy": {
                    "signingRules": {
                        "extensionSigned": case['global_signing_rule']
                    },
                    "allowListOnly": case['allowlist_rule']
                },
                "azureGuestExtensionsPolicy": {
                    TEST_EXT_NAME: {
                        "signingRules": {
                            "extensionSigned": False
                        }
                    }
                }
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                with patch('azurelinuxagent.ga.policy.policy_engine.ExtensionPolicyEngine.get_policy_file',
                           return_value=policy_file.name):
                    with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
                        with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                       return_value=True):
                                engine = ExtensionPolicyEngine(test_ext_handler)
                                download_allowed =  engine.is_extension_download_allowed()
                                self.assertTrue(download_allowed, msg="Extension is not signed, but individual signing rule is false, "
                                                "so download should be allowed.")

    def test_unsigned_extension_should_be_allowed_if_global_signing_rule_false_and_no_individual_rule(self):
        """
        If allowlist rule is false and global signing rule false (no individual rule), unsigned extension should be allowed.
        """
        test_ext_handler = Extension(name=TEST_EXT_NAME)  # We don't set the signature field, so extension is unsigned.
        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": False
                },
                "allowListOnly": False
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            with patch('azurelinuxagent.ga.policy.policy_engine.ExtensionPolicyEngine.get_policy_file',
                       return_value=policy_file.name):
                with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
                    with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                        with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                   return_value=True):
                            engine = ExtensionPolicyEngine(test_ext_handler)
                            download_allowed = engine.is_extension_download_allowed()
                            self.assertTrue(download_allowed,
                                            msg="Extension is not signed, but global signing rule is false, "
                                                "so download should be allowed.")

    def test_unsigned_extension_should_raise_exception_if_global_signing_rule_true_and_no_individual_rule(self):
        """
        If allowlist rule is false and global signing rule true (no individual rule), unsigned exception should be denied.
        is_extension_download_allowed() should throw a PolicyError.
        """
        test_ext_handler = Extension(name=TEST_EXT_NAME)  # We don't set the signature field, so extension is unsigned.
        policy = {
            "azureGuestAgentPolicy": {
                "signingRules": {
                    "extensionSigned": True
                },
                "allowListOnly": False
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            with patch('azurelinuxagent.ga.policy.policy_engine.ExtensionPolicyEngine.get_policy_file',
                       return_value=policy_file.name):
                with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu'):
                    with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04'):
                        with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled',
                                   return_value=True):
                            engine = ExtensionPolicyEngine(test_ext_handler)
                            with self.assertRaises(PolicyError,
                                                   msg="Extension is not signed and global signing rule is true, "
                                                       "so download should not be allowed."):
                                engine.is_extension_download_allowed()

