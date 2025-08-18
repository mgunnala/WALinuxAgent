# Windows Azure Linux Agent
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
# Requires Python 2.6+ and Openssl 1.0+
#
import os
import subprocess
from azurelinuxagent.common import logger
from azurelinuxagent.common import conf
from azurelinuxagent.common import event
from azurelinuxagent.common.event import WALAEventOperation


_MICROSOFT_ROOT_CERT_2011_03_22 = """-----BEGIN CERTIFICATE-----
MIIF7TCCA9WgAwIBAgIQP4vItfyfspZDtWnWbELhRDANBgkqhkiG9w0BAQsFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEw
MzIyMjIwNTI4WhcNMzYwMzIyMjIxMzA0WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
aWNhdGUgQXV0aG9yaXR5IDIwMTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCygEGqNThNE3IyaCJNuLLx/9VSvGzH9dJKjDbu0cJcfoyKrq8TKG/Ac+M6
ztAlqFo6be+ouFmrEyNozQwph9FvgFyPRH9dkAFSWKxRxV8qh9zc2AodwQO5e7BW
6KPeZGHCnvjzfLnsDbVU/ky2ZU+I8JxImQxCCwl8MVkXeQZ4KI2JOkwDJb5xalwL
54RgpJki49KvhKSn+9GY7Qyp3pSJ4Q6g3MDOmT3qCFK7VnnkH4S6Hri0xElcTzFL
h93dBWcmmYDgcRGjuKVB4qRTufcyKYMME782XgSzS0NHL2vikR7TmE/dQgfI6B0S
/Jmpaz6SfsjWaTr8ZL22CZ3K/QwLopt3YEsDlKQwaRLWQi3BQUzK3Kr9j1uDRprZ
/LHR47PJf0h6zSTwQY9cdNCssBAgBkm3xy0hyFfj0IbzA2j70M5xwYmZSmQBbP3s
MJHPQTySx+W6hh1hhMdfgzlirrSSL0fzC/hV66AfWdC7dJse0Hbm8ukG1xDo+mTe
acY1logC8Ea4PyeZb8txiSk190gWAjWP1Xl8TQLPX+uKg09FcYj5qQ1OcunCnAfP
SRtOBA5jUYxe2ADBVSy2xuDCZU7JNDn1nLPEfuhhbhNfFcRf2X7tHc7uROzLLoax
7Dj2cO2rXBPB2Q8Nx4CyVe0096yb5MPa50c8prWPMd/FS6/r8QIDAQABo1EwTzAL
BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUci06AjGQQ7kU
BU7h6qfHMdEjiTQwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQELBQADggIB
AH9yzw+3xRXbm8BJyiZb/p4T5tPw0tuXX/JLP02zrhmu7deXoKzvqTqjwkGw5biR
nhOBJAPmCf0/V0A5ISRW0RAvS0CpNoZLtFNXmvvxfomPEf4YbFGq6O0JlbXlccmh
6Yd1phV/yX43VF50k8XDZ8wNT2uoFwxtCJJ+i92Bqi1wIcM9BhS7vyRep4TXPw8h
Ir1LAAbblxzYXtTFC1yHblCk6MM4pPvLLMWSZpuFXst6bJN8gClYW1e1QGm6CHmm
ZGIVnYeWRbVmIyADixxzoNOieTPgUFmG2y/lAiXqcyqfABTINseSO+lOAOzYVgm5
M0kS0lQLAausR7aRKX1MtHWAUgHoyoL2n8ysnI8X6i8msKtyrAv+nlEex0NVZ09R
s1fWtuzuUrc66U7h14GIvE+OdbtLqPA1qibUZ2dJsnBMO5PcHd94kIZysjik0dyS
TclY6ysSXNQ7roxrsIPlAT/4CTL2kzU0Iq/dNw13CYArzUgA8YyZGUcFAenRv9FO
0OYoQzeZpApKCNmacXPSqs0xE2N2oTdvkjgefRI8ZjLny23h/FKJ3crWZgWalmG+
oijHHKOnNlA8OqTfSm7mhzvO6/DggTedEzxSjr25HTTGHdUKaj2YKXCMiSrRq4IQ
SB/c9O+lxbtVGjhjhE63bK2VVOxlIhBJF7jAHscPrFRH
-----END CERTIFICATE-----"""

_SELF_SIGNED_TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUEOWLdeQFJoEAcT8LqFuGoWgcskUwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIdGVzdGNlcnQwHhcNMjUwODE4MTY1NzI2WhcNMjcwODE4
MTY1NzI2WjATMREwDwYDVQQDDAh0ZXN0Y2VydDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAOHOtr3HNJDfk/SNEct+AINwD48AsnXt8qU9aEmKBqwXD8Nv
OQs/ZtCxIwc2+OGfeHWyw9IHBhJzewZMDCgsmKPMoD+ZUcBLHHdX/711BDn7h2md
FKhM3gyV6OXwD/GvCxtgebcMy8iKS+7wDI52HaJg0epXtesfw7P3KLC6nkomoX6J
Qfow8PhnwoLdzZV41mP+YS6sMtOea60dSlskMtXulpLMUW6xaQi0w1EgFLQDQI6j
eB6VzNKDuV8Vvgts3agcz4lyQ+YnQ7Sy0ogfgJRU1/5yNLk+lV/+ARFrJvlhJXFo
BqAvqgNMySjPKJ/O5IQJApx5GCN+cXD5OZHzW38CAwEAAaNTMFEwHQYDVR0OBBYE
FHawlOYiAZ1jQZxPKtZZvzO11BJhMB8GA1UdIwQYMBaAFHawlOYiAZ1jQZxPKtZZ
vzO11BJhMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBALtNoD+0
t0B1g+CTJz7iBv1Nqmzx7t4AE1SEDPifuelJhBGbCXgje6IVZinvFCRDWbsI04eM
IbWH4og7joAgvoj9O5Wc0hlMxjPLfBKZndtLnMDlyH93GDPNfURoId6bhicsqezT
5xyc8UiXSihxhzU5Y32kutJ3P73JZDhzQfceIrUReQUEsVc4HtEjkpUyau0ZI456
pIos9UYyocSHjPgiFXuRr49d5o+HVP1N9ZzQSY8mlrMq3zpoEFMcauTQ90qEu9md
7j1wWA/8MA1eA22/WBJhSR+TTyv0VXjsQt0Aqhtu0Lj7ugpcm917ejBZCLaie3MR
bEOvNR4yokT8CPk=
-----END CERTIFICATE-----"""


def get_microsoft_signing_certificate_path():
    return os.path.join(conf.get_lib_dir(), "microsoft_root_certificate.pem")


def _write_certificate(cert_string, output_path):
    """
    Write certificate string to file specified by output path. Overwrite file if it already exists.
    """
    umask = None
    try:
        # Only owner should have read-write permissions on file creation (600)
        umask = os.umask(0o077)
        with open(output_path, "w") as cert_file:
            cert_file.write(cert_string)
        logger.info("Signing certificate written to {0}".format(output_path))

    except Exception as err:
        msg = "Failed to write signing certificate to file ('{0}'). Error details:\n{1}".format(output_path, err)
        event.error(op=WALAEventOperation.SignatureValidation, fmt=msg)

    finally:
        if umask is not None:
            os.umask(umask)

def write_signing_certificates():
    """
    Write root certificates to the library directory (directory specified in conf.py).
    We store root certificates as strings and then write them to a file on agent init. Both the baked-in and
    self-update agent can use the same file path for the certificates.
    """
    _write_certificate(_MICROSOFT_ROOT_CERT_2011_03_22, get_microsoft_signing_certificate_path())
    _write_certificate(_SELF_SIGNED_TEST_CERT, os.path.join(conf.get_lib_dir(), "self_signed_test_cert.pem"))
