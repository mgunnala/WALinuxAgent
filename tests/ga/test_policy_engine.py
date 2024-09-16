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

from tests.lib.tools import AgentTestCase
from azurelinuxagent.ga.policy.policy_engine import ExtensionPolicyEngine, PolicyEngine, POLICY_SUPPORTED_DISTROS_MIN_VERSIONS, PolicyError
from tests.lib.tools import patch, data_dir
from azurelinuxagent.common.protocol.restapi import Extension

TEST_EXTENSION_NAME = "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux"


class TestPolicyEngine(AgentTestCase):

    def test_should_enable_policy_on_all_supported_distro(self):
        """Policy should be enabled on all supported distros."""
        for distro_name, version in POLICY_SUPPORTED_DISTROS_MIN_VERSIONS.items():
            with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new=distro_name):
                with patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new=version):
                    with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                        engine = PolicyEngine()
                        self.assertTrue(engine.is_policy_enforcement_feature_enabled(), "Policy should be enabled on supported distro {0} {1}".format(distro_name, version))

    def test_should_raise_exception_when_enabling_policy_on_unsupported_distro(self):
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
                            PolicyEngine()

    def test_should_raise_exception_on_unsupported_architecture(self):
        """Policy should NOT be enabled on ARM64."""
        # TODO: remove this test when support for ARM64 is added.
        with patch('azurelinuxagent.ga.policy.policy_engine.get_osutil') as mock_get_osutil:
            with patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                with self.assertRaises(PolicyError, msg="Policy should not be enabled on unsupported architecture ARM64, should have raised exception."):
                    mock_get_osutil.get_vm_arch.return_value = "arm64"
                    PolicyEngine()


class TestExtensionPolicyEngine(AgentTestCase):
    def setUp(self):
        self.custom_policy_path = os.path.join(data_dir, 'policy', "waagent_policy.json")   # Path where we should create custom policy files for tests.

        # Patch attributes to enable policy feature
        self.patcher_custom_policy_path = patch('azurelinuxagent.ga.policy.policy_engine.CUSTOM_POLICY_PATH', new=self.custom_policy_path)
        self.patcher_custom_policy_path.start()
        self.patcher_distro_name = patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_NAME', new='ubuntu')
        self.patcher_distro_name.start()
        self.patcher_distro_version = patch('azurelinuxagent.ga.policy.policy_engine.DISTRO_VERSION', new='20.04')
        self.patcher_distro_version.start()
        self.patcher_enabled = patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True)
        self.patcher_enabled.start()

        AgentTestCase.setUp(self)

    def tearDown(self):
        # Clean up any custom policy file we created
        if os.path.exists(self.custom_policy_path):
            os.remove(self.custom_policy_path)
        patch.stopall()
        AgentTestCase.tearDown(self)

    def test_should_allow_and_should_not_enforce_signature_for_default_policy(self):
        """
        Default policy should allow all extensions and not enforce signature.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_allow = engine.should_allow_extension()
        self.assertTrue(should_allow, msg="Default policy should allow all extensions.")
        should_enforce = engine.should_enforce_signature()
        self.assertTrue(not should_enforce, msg="Default policy should not enforce extension signature.")

    def test_should_allow_if_allowListedExtensionsOnly_true_and_extension_in_list(self):
        """
        If allowListedExtensionsOnly is true and extension in list, should_allow = True.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "signingPolicy": {},
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": False,
                            "signingPolicy": {},
                            "runtimePolicy": {}
                        }
                    }
                },
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_allow = engine.should_allow_extension()
            self.assertTrue(should_allow, msg="Extension is in allowlist, so should be allowed.")

    def test_should_not_allow_if_allowListedExtensionsOnly_true_and_extension_not_in_list(self):
        """
        If allowListedExtensionsOnly is true and extension not in list, should_allow = False.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "signingPolicy": {},
                    "extensions": {}    # Extension not in allowed list.
                },
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_allow = engine.should_allow_extension()
            self.assertFalse(should_allow, msg="allowListedExtensionsOnly is true and extension is not in allowlist, so should not be allowed.")

    def test_should_allow_if_allowListedExtensionsOnly_false(self):
        """
        If allowListedExtensionsOnly is false, should_allow = True (whether extension in list or not).
        """

        # Test an extension in the allowlist, and an extension not in the allowlist. Both should be allowed.
        test_ext_in_list = Extension(name=TEST_EXTENSION_NAME)
        test_ext_not_in_list = Extension(name="Random.Ext")
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": False,
                    "signatureRequired": False,
                    "signingPolicy": {},
                    "extensions": {
                        TEST_EXTENSION_NAME: {
                            "signatureRequired": False,
                            "signingPolicy": {},
                            "runtimePolicy": {}
                        }
                    }
                },
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine1 = ExtensionPolicyEngine(test_ext_in_list)
            self.assertTrue(engine1.should_allow_extension(), msg="allowListedExtensionsOnly is false, so extension should be allowed.")
            engine2 = ExtensionPolicyEngine(test_ext_not_in_list)
            self.assertTrue(engine2.should_allow_extension(), msg="allowListedExtensionsOnly is false, so extension should be allowed.")

    def test_should_enforce_signature_if_individual_enforceSignature_true(self):
        """
        If signatureRequired is true for individual extension, should_enforce_signature = True (whether global signatureRequired is true or false).
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        global_signature_rule_cases = [True, False]
        for global_rule in global_signature_rule_cases:
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": False,
                        "signatureRequired": global_rule,
                        "signingPolicy": {},
                        "extensions": {
                            TEST_EXTENSION_NAME: {
                                "signatureRequired": True,
                                "signingPolicy": {},
                                "runtimePolicy": {}
                            }
                        }
                    },
                    "jitPolicies": {}
                }

            with open(self.custom_policy_path, mode='w') as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = ExtensionPolicyEngine(test_extension)
                should_enforce_signature = engine.should_enforce_signature()
                self.assertTrue(should_enforce_signature, msg="Individual signatureRequired policy is true, so signature should be enforced.")

    def test_should_not_enforce_signature_if_individual_enforceSignature_false(self):
        """
        If signatureRequired is false for individual extension policy, should_enforce_signature = False (whether global signatureRequired is true or false).
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        global_signature_rule_cases = [True, False]
        for global_rule in global_signature_rule_cases:
            policy = \
                {
                    "policyVersion": "0.1.0",
                    "extensionPolicies": {
                        "allowListedExtensionsOnly": False,
                        "signatureRequired": global_rule,
                        "signingPolicy": {},
                        "extensions": {
                            TEST_EXTENSION_NAME: {
                                "signatureRequired": False,
                                "signingPolicy": {},
                                "runtimePolicy": {}
                            }
                        }
                    },
                    "jitPolicies": {}
                }

            with open(self.custom_policy_path, mode='w') as policy_file:
                json.dump(policy, policy_file, indent=4)
                policy_file.flush()
                engine = ExtensionPolicyEngine(test_extension)
                should_enforce_signature = engine.should_enforce_signature()
                self.assertFalse(should_enforce_signature,
                                msg="Individual signatureRequired policy is false, so signature should be not enforced.")

    def test_should_enforce_signature_if_global_enforceSignature_true_and_no_individual_policy(self):
        """
        If signatureRequired is true globally and no individual extension signature policy, should_enforce_signature = True.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": True,
                    "signingPolicy": {},
                    "extensions": {}
                },
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_enforce_signature = engine.should_enforce_signature()
            self.assertTrue(should_enforce_signature,
                            msg="Global signatureRequired policy is true, so signature should be enforced.")

    def test_should_not_enforce_signature_if_global_enforceSignature_false_and_no_individual_policy(self):
        """
        If signatureRequired is false globally and no individual extension signature policy, should_enforce_signature = False.
        """
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "signingPolicy": {},
                    "extensions": {}
                },
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_enforce_signature = engine.should_enforce_signature()
            self.assertFalse(should_enforce_signature,
                             msg="Global signatureRequired policy is false, so signature should not be enforced.")

    def test_should_enforce_signature_if_no_custom_policy_present(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_enforce_signature = engine.should_enforce_signature()
        self.assertFalse(should_enforce_signature, msg="No custom policy is present, so use default policy. Should not enforce signature.")

    def test_should_allow_if_no_custom_policy_present(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_allow = engine.should_allow_extension()
        self.assertTrue(should_allow, msg="No custom policy is present, so use default policy. Should allow all extensions.")

    def test_should_raise_error_if_custom_policy_contains_unexpected_attribute(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extentionPolicies": {       # Note that this attribute is misspelled.
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "signingPolicy": {},
                    "extensions": {}
                },
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            with self.assertRaises(ValueError, msg="'extentionPolicies' is an unexpected attribute, should raise an error."):
                ExtensionPolicyEngine(test_extension)

    def test_should_raise_error_if_custom_policy_contains_invalid_type(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": "True",    # String instead of boolean, should raise error.
                    "signatureRequired": False,
                    "signingPolicy": {},
                    "extensions": {}
                },
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            with self.assertRaises(ValueError, msg="String used instead of boolean, should raise error."):
                ExtensionPolicyEngine(test_extension)

    def test_should_allow_if_extension_policy_section_missing(self):
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        policy = \
            {
                "policyVersion": "0.1.0",
                "jitPolicies": {}
            }
        with open(self.custom_policy_path, mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()
            engine = ExtensionPolicyEngine(test_extension)
            should_allow = engine.should_allow_extension()
            self.assertTrue(should_allow)

    def test_should_allow_if_policy_disabled(self):
        self.patcher_enabled.stop()     # Turn off the policy feature enablement
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_allow = engine.should_allow_extension()
        self.assertTrue(should_allow,
                         msg="Policy feature is disabled, so all extensions should be allowed.")

    def test_should_not_enforce_signature_if_policy_disabled(self):
        self.patcher_enabled.stop()     # Turn off the policy feature enablement
        test_extension = Extension(name=TEST_EXTENSION_NAME)
        engine = ExtensionPolicyEngine(test_extension)
        should_enforce_signature = engine.should_enforce_signature()
        self.assertFalse(should_enforce_signature,
                         msg="Policy feature is disabled, so signature should not be enforced.")
