#!/usr/bin/env python3

# Microsoft Azure Linux Agent
#
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
import json

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.agent_test_context import AgentVmTestContext
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import CommandError
from tests_e2e.tests.lib.ssh_client import SshClient
import datetime
import pytz
import uuid

from assertpy import assert_that, fail
from typing import Any

from azure.mgmt.compute.models import VirtualMachineInstanceView

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient


class ExtensionPolicy(AgentVmTest):
    """
    """
    class TestCase:
        def __init__(self, extension: VirtualMachineExtensionClient, settings: Any):
            self.extension = extension
            self.settings = settings

    def __init__(self, context: AgentVmTestContext):
        super().__init__(context)
        self._ssh_client: SshClient = self._context.create_ssh_client()

    def check_agent_log_contains(self, data, assertion):
        try:
            self._ssh_client.run_command("grep \"{0}\" /var/log/waagent.log".format(data))
        except CommandError:
            fail("{0}".format(assertion))

    def _create_policy_file(self, policy):
        with open("waagent_policy.json", mode='w') as policy_file:
            json.dump(policy, policy_file, indent=4)
            policy_file.flush()

            remote_path = "/tmp/waagent_policy.json"
            local_path = policy_file.name
            self._ssh_client.copy_to_node(local_path=local_path, remote_path=remote_path)
            policy_file_final_dest = "/etc/waagent_policy.json"
            log.info("Copying policy file to test VM [%s]", self._context.vm.name)
            self._ssh_client.run_command(f"mv {remote_path} {policy_file_final_dest}", use_sudo=True)

    def _operation_should_succeed(self, operation, extension_case):
        log.info(f"Attempting to {operation} {extension_case.extension.__str__()}, expected to succeed ")
        try:
            if operation == "enable":
                extension_case.extension.enable(settings=extension_case.settings, force_update=True, timeout=15 * 60)
            elif operation == "delete":
                extension_case.extension.delete(timeout=15 * 60)
            log.info(f"Operation '{operation}' for {extension_case.extension.__str__()} succeeded as expected.")
        except Exception as error:
            fail(
                f"Unexpected error while trying to {operation} {extension_case.extension.__str__()}. "
                f"Extension is allowed by policy so this operation should have completed successfully.\n"
                f"Error: {error}")

    def _operation_should_fail(self, operation, extension_case):
        log.info(f"Attempting to {operation} {extension_case.extension.__str__()}, should fail fast.")
        try:
            timeout = (6 * 60)  # Fail fast.
            if operation == "enable":
                extension_case.extension.enable(settings=extension_case.settings, force_update=True, timeout=timeout)
            elif operation == "delete":
                extension_case.extension.delete(timeout=timeout)
            fail(f"The agent should have reported an error trying to {operation} {extension_case.extension.__str__()} "
                 f"because the extension is disallowed by policy.")
        except Exception as error:
            assert_that("Extension is disallowed by agent policy and will not be processed" in str(error)) \
                .described_as(
                f"Error message should communicate that extension is disallowed by policy, but actual error "
                f"was: {error}").is_true()
            log.info(f"Extension {operation} failed as expected")

    def run(self):

        # Prepare extensions to test
        unique = str(uuid.uuid4())
        test_file = f"waagent-test.{unique}"
        custom_script = ExtensionPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript,
                                          resource_name="CustomScript"),
            {'commandToExecute': f"echo '{unique}' > /tmp/{test_file}"}
        )
        run_command = ExtensionPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                          resource_name="RunCommandHandler"),
            {'source': {'script': f"echo '{unique}' > /tmp/{test_file}"}}
        )
        azure_monitor = ExtensionPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.AzureMonitorLinuxAgent,
                                          resource_name="AzureMonitorLinuxAgent"),
            None
        )
        unique2 = str(uuid.uuid4())
        test_file2 = f"waagent-test.{unique2}"
        run_command_2 = ExtensionPolicy.TestCase(
            VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                          resource_name="RunCommandHandler2"),
            {'source': {'script': f"echo '{unique2}' > /tmp/{test_file2}"}}
        )

        # Enable policy via conf
        log.info("Enabling policy via conf file on the test VM [%s]", self._context.vm.name)
        self._ssh_client.run_command("update-waagent-conf Debug.EnableExtensionPolicy=y", use_sudo=True)

        # Test case 1: should only enable allowlisted extensions
        # CustomScript should be enabled, RunCommand and AzureMonitor should fail.
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {
                        "Microsoft.Azure.Extensions.CustomScript": {}
                    }
                }
            }
        self._create_policy_file(policy)
        self._operation_should_succeed("enable", custom_script)
        self._operation_should_fail("enable", run_command)
        self._operation_should_fail("enable", azure_monitor)

        # Test case 2: turn allowlist off
        # RunCommand should be successfully enabled and then deleted.
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": False,
                    "signatureRequired": False,
                    "extensions": {}
                }
            }
        self._create_policy_file(policy)
        self._operation_should_succeed("enable", run_command)
        self._operation_should_succeed("delete", run_command)

        # Test case 3: uninstall should fail when disallowed
        # Remove CustomScript from allowlist and try to uninstall, should fail.
        policy = \
            {
                "policyVersion": "0.1.0",
                "extensionPolicies": {
                    "allowListedExtensionsOnly": True,
                    "signatureRequired": False,
                    "extensions": {}
                }
            }
        self._create_policy_file(policy)

        # Known issue - this will not fail fast because we are not passing any settings here
        # We end up creating a handler status but not an extension status, so we don't fail fast
        # self._delete_should_fail(custom_script)

        # Test case 4: both instances in a multiconfig extension should fail, if disallowed.
        # Disallow RunCommand and try to install two instances, both should fail fast.
        self._operation_should_fail("enable", run_command)
        self._operation_should_fail("enable", run_command_2)


if __name__ == "__main__":
    ExtensionPolicy.run_from_command_line()