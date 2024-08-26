# use open ssl

import base64
from azurelinuxagent.common.utils.shellutil import run_command


def convert_signature(sig_string, output_file):
    """
    Convert the signature string to a binary file, and write to the output file.
    """
    sig = sig_string.strip()
    bin_sig = base64.b64decode(sig)
    with open(output_file, "wb") as f:
        f.write(bin_sig)
    a = bin_sig


def verify_signature(p7b_path, ext_path, cert_path):
    command = [
        'openssl', 'cms', '-verify', '-binary', '-inform', 'der',
        '-in', p7b_path, '-content', ext_path, '-purpose', 'any',
        '-CAfile', cert_path, '-attime', '1717452097'
    ]
    try:
        result = run_command(command)
        return True
    except Exception as ex:
        code = ex.returncode
        if code == 1:
            msg = "An error occurred parsing the command options."
        elif code == 2:
            msg = "Input file could not be read."
        elif code == 3:
            msg = "An error occurred creating the CMS file or reading the MIME message."
        elif code == 4:
            msg = "An error occurred decrypting or verifying the contents."
        elif code == 5:
            msg = "Content was verified but an error occurred writing out the signers certificates."
        else:
            msg = "Unknown error occurred during signature validation."
        raise ex
