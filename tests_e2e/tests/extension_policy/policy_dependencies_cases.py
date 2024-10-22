def add_one_dependent_ext_without_settings():
    # Dependent extensions without settings should be enabled with dependencies
    return [
        {
            "name": "AzureMonitorLinuxAgent",
            "properties": {
                "provisionAfterExtensions": ["CustomScript"],
                "publisher": "Microsoft.Azure.Monitor",
                "type": "AzureMonitorLinuxAgent",
                "typeHandlerVersion": "1.5",
                "autoUpgradeMinorVersion": True
            }
        },
        {
            "name": "CustomScript",
            "properties": {
                "publisher": "Microsoft.Azure.Extensions",
                "type": "CustomScript",
                "typeHandlerVersion": "2.1",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "commandToExecute": "date"
                }
            }
        }
    ]



def _should_fail_sc_depends_on_disallowed_sc():
    return []
def _should_fail_sc_depends_on_disallowed_nc():
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
    template = \
        [
            {
                "name": "AzureMonitorLinuxAgent",
                "properties": {
                    "provisionAfterExtensions": [],
                    "publisher": "Microsoft.Azure.Monitor",
                    "type": "AzureMonitorLinuxAgent",
                    "typeHandlerVersion": "1.5",
                    "autoUpgradeMinorVersion": True
                }
            },
            {
                "name": "CustomScript",
                "properties": {
                    "provisionAfterExtensions": ["AzureMonitorLinuxAgent"],
                    "publisher": "Microsoft.Azure.Extensions",
                    "type": "CustomScript",
                    "typeHandlerVersion": "2.1",
                    "autoUpgradeMinorVersion": True,
                    "settings": {
                        "commandToExecute": "date"
                    }
                }
            }
        ]
    return (policy, template)


def _should_fail_sc_depends_on_disallowed_mc():
    return []

def _should_fail_mc_depends_on_disallowed_mc():
    return []

def _should_fail_mc_depends_on_disallowed_sc():
    return []

def _should_fail_mc_depends_on_disallowed_nc():
    return []
