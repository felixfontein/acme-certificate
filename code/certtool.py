#!/usr/bin/env python
"""Command line interface for the compact ACME library."""

import argparse
import re
import subprocess
import sys
import textwrap

if not hasattr(textwrap, 'indent'):
    # Monkey-patching for Python 2, whose textwrap has no indent() function:

    def indent(text, prefix, predicate=None):
        lines = text.splitlines(True)
        if predicate:
            return ''.join([prefix + line for line in lines if predicate(line)])
        else:
            return ''.join([prefix + line for line in lines])

    textwrap.indent = indent


# #####################################################################################################
# # Helper functions


def _run_openssl(args, input=None):
    """Execute OpenSSL with the given arguments. Feeds input via stdin if given."""
    if input is None:
        proc = subprocess.Popen(['openssl'] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
    else:
        proc = subprocess.Popen(['openssl'] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(input)
    if proc.returncode != 0:
        raise IOError('OpenSSL Error: {0}'.format(err.decode('utf-8')))
    return out


# #####################################################################################################
# # Algorithm support


class Algorithm(object):
    """Abstracts an algorithm (RSA or ECC)."""

    def __init__(self, name):
        """Initialize algorithm object."""
        self.name = name

    def __not_implemented(self, method):
        """Helper method to raise not implemented errors."""
        raise Exception('Algorithm {0} does not support {1}!'.format(self.name, method))

    def create_key(self, key_length):
        """Create a private key of given length."""
        self.__not_implemented('create_key')


class RSA(Algorithm):
    """Abstracts the RSA algorithm."""

    def __init__(self):
        """Create new RSA algorithm object."""
        super(RSA, self).__init__('RSA')

    def create_key(self, key_length):
        """Generate RSA key with given key length."""
        return _run_openssl(['genrsa', str(key_length)]).decode('utf-8')


class ECC(Algorithm):
    """Abstracts Elliptic Curve based algorithms."""

    def __init__(self, curve, openssl_curve, bitlength):
        """Create new ECC algorithm object for given JOSE curve name, OpenSSL curve name, and bit length."""
        super(ECC, self).__init__('ECC-{0}'.format(curve))
        self.curve = curve
        self.openssl_curve = openssl_curve
        self.bitlength = bitlength

    def create_key(self, key_length):
        """Generate ECC private key for this curve. The key length is ignored."""
        if key_length < 2048:
            sys.stderr.write('WARNING: creating RSA key with less than 2048 bits!\n')
        return _run_openssl(['ecparam', '-name', self.openssl_curve, '-genkey', '-noout']).decode('utf-8')


ALGORITHMS = {
    'rsa': RSA(),
    'p-256': ECC('p-256', 'prime256v1', 256),
    'p-384': ECC('p-384', 'secp384r1', 384),
    # 'p-521': ECC('p-521', 'secp521r1', 528),  -- P-521 isn't supported yet (on Let's Encrypt staging server);
    #                                              see https://github.com/letsencrypt/boulder/issues/2217
}


def _get_algorithm(algorithm):
    if algorithm not in ALGORITHMS:
        raise ValueError("Unknown algorithm '{0}'!".format(algorithm))
    return ALGORITHMS[algorithm]


# #####################################################################################################
# # Low level functions


def read_stdin():
    """Read data from stdin."""
    if sys.version_info < (3, 0):
        return sys.stdin.read()
    else:
        return sys.stdin.buffer.read()


def write_file(filename, content):
    """Write the contents (string) into the file, encoded with UTF-8."""
    with open(filename, "wb") as f:
        f.write(content.encode('utf-8'))


def create_key(key_length=4096, algorithm='rsa'):
    """Create an RSA key with the given key length in bits."""
    algorithm = _get_algorithm(algorithm)
    return algorithm.create_key(key_length)


def generate_csr(key_filename, config_filename, domains, must_staple=False):
    """Given a private key and a list of domains, create a Certificate Signing Request (CSR).

    ``must_staple```: if set to ``True``, asks for a certificate with OCSP Must Staple enabled.
    """
    # First generate config
    template = '''HOME     = .
RANDFILE = $ENV::HOME/.rnd

[req]
distinguished_name = req_DN
req_extensions     = req_SAN

[req_DN]

[req_SAN]
subjectAltName = {0}
'''
    if must_staple:
        # See https://tools.ietf.org/html/rfc7633#section-6 and https://scotthelme.co.uk/ocsp-must-staple/
        template += '1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05\n'
        # For OpenSSL 1.1.0 or newer, we can use
        #     template += 'tlsfeature = status_request\n'
        # instead.
    write_file(config_filename, template.format(','.join(['DNS:{0}'.format(domain) for domain in domains])))
    # Generate CSR
    if key_filename == '/dev/stdin':
        stdin = read_stdin()
        return _run_openssl(['req', '-new', '-sha256', '-key', '/dev/stdin', '-subj', '/', '-config', config_filename], input=stdin).decode('utf-8')
    else:
        return _run_openssl(['req', '-new', '-sha256', '-key', key_filename, '-subj', '/', '-config', config_filename]).decode('utf-8')


def get_csr_as_text(csr_filename):
    """Convert CSR file to plaintext with OpenSSL."""
    return _run_openssl(['req', '-in', csr_filename, '-noout', '-text']).decode('utf-8')


def parse_csr(csr_as_text):
    """Parse a Certificate Signing Request (CSR).

    Returns the list of domains this CSR affects.
    """
    domains = set([])
    common_name = re.search(r'Subject:.*? CN\s*=\s*([^\s,;/]+)', csr_as_text)
    if common_name is not None:
        domains.add(common_name.group(1))
    for subject_alt_names in re.finditer(r'X509v3 Subject Alternative Name: \n +([^\n]+)\n', csr_as_text, re.MULTILINE | re.DOTALL):
        for san in subject_alt_names.group(1).split(', '):
            if san.startswith('DNS:'):
                domains.add(san[4:])
    return sorted(domains)


# #####################################################################################################
# # High level (CLI) functions


def cli_gen_account_key(account_key, key_length, algorithm):
    key = create_key(key_length=key_length, algorithm=algorithm)
    write_file(account_key, key)


def cli_gen_cert_key(key, key_length, algorithm):
    the_key = create_key(key_length=key_length, algorithm=algorithm)
    write_file(key, the_key)


def cli_gen_csr(domains, key, csr, must_staple):
    if csr.endswith('.csr'):
        config_filename = csr[:-4] + '.cnf'
    else:
        config_filename = csr + '.cnf'
    sys.stderr.write('Writing OpenSSL config to {0}.\n'.format(config_filename))
    the_csr = generate_csr(key, config_filename, domains.split(','), must_staple=must_staple)
    write_file(csr, the_csr)


def cli_print_csr(csr):
    csr_as_text = get_csr_as_text(csr)
    sys.stdout.write('Domain names: {0}\n\n'.format(', '.join(parse_csr(csr_as_text))))
    sys.stdout.write(csr_as_text + '\n')


if __name__ == '__main__':
    try:
        commands = {
            'gen-account-key': {
                'help': 'Generates an account key.',
                'requires': ['account_key'],
                'optional': ['key_length', 'algorithm'],
                'command': cli_gen_account_key,
            },
            'gen-key': {
                'help': 'Generates a certificate key.',
                'requires': ['key'],
                'optional': ['key_length', 'algorithm'],
                'command': cli_gen_cert_key,
            },
            'gen-csr': {
                'help': 'Generates a certificate signing request (CSR). Under *nix, use /dev/stdin after --key to provide key via stdin.',
                'requires': ['domains', 'key', 'csr'],
                'optional': ['must_staple'],
                'command': cli_gen_csr,
            },
            'print-csr': {
                'help': 'Prints the given certificate signing request (CSR) in human-readable form.',
                'requires': ['csr'],
                'optional': [],
                'command': cli_print_csr,
            },
        }
        additional_description = ['']
        additional_description.append('More information on the available commands:'.format(', '.join('"{0}"'.format(command) for command in sorted(commands.keys()))))
        additional_description.append('')
        for command in sorted(commands.keys()):
            cmd = commands[command]
            additional_description.append('  {0}:'.format(command))
            additional_description.append('{0}'.format(textwrap.indent('\n'.join(textwrap.wrap(cmd['help'])), prefix='    ')))
            if cmd['requires']:
                additional_description.append('    Mandatory options: {0}'.format(', '.join(['--{0}'.format(opt.replace('_', '-')) for opt in cmd['requires']])))
            if cmd['optional']:
                additional_description.append('    Optional options: {0}'.format(', '.join(['--{0}'.format(opt.replace('_', '-')) for opt in cmd['optional']])))

        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=textwrap.dedent(R'''
                This script provides convenience functions for account key, certificate
                private key and certificate signing request handling.

                The following example commands create a Let's Encrpyt account key,
                a private key for a certificate, a certificate signing request (CSR)
                for the generated key and for the two domains example.com and
                www.example.com, and prints the CSR in human-readable form.
                =====================================================================
                python certtool.py gen-account-key --account-key /path/to/account.key
                python certtool.py gen-key --key /path/to/domain.key
                python certtool.py gen-csr --key /path/to/domain.key \
                                           --csr /path/to/domain.csr \
                                           --domains example.com,www.example.com
                python certtool.py print-csr --csr /path/to/domain.csr
                =====================================================================

                Also note that by default, RSA keys are generated. If you want ECC keys,
                please specify "--algorithm <alg>" with <alg> being "p-256" or "p-384".
                '''),
            epilog = '\n'.join(additional_description)
        )
        parser.add_argument('command', type=str, nargs='?', help='must be one of {0}'.format(', '.join('"{0}"'.format(command) for command in sorted(commands.keys()))))
        parser.add_argument('--account-key', required=False, help="path to your Let's Encrypt account private key")
        parser.add_argument('--algorithm', required=False, default='rsa', help='the algorithm to use ({0})'.format(', '.join(sorted(ALGORITHMS.keys()))))
        parser.add_argument('--key-length', type=int, default=4096, required=False, help='key length for private keys')
        parser.add_argument('--key', required=False, help="path to your certificate's private key")
        parser.add_argument('--csr', required=False, help="path to your certificate signing request (CSR)")
        parser.add_argument('-d', '--domains', required=False, default=None, help='a comma-separated list of domain names')
        parser.add_argument('--must-staple', required=False, default=False, action='store_true', help='request must staple extension for certificate')

        args = parser.parse_args()
        if args.command is None:
            parser.print_help()
            sys.exit(-1)
        elif args.command not in commands:
            sys.stderr.write("Unknown command '{0}'! Command must be one of {1}.\n".format(args.command, ', '.join('"{0}"'.format(command) for command in sorted(commands.keys()))))
            sys.exit(-1)
        else:
            cmd = commands[args.command]
            accepted = set()
            values = {}
            for req in cmd['requires']:
                accepted.add(req)
                if args.__dict__[req] is None:
                    sys.stderr.write("Command '{0}' requires that option '{1}' is set!\n".format(args.command, req))
                    sys.exit(-1)
                values[req] = args.__dict__[req]
            for opt in cmd['optional']:
                accepted.add(opt)
                values[opt] = args.__dict__[opt]
            for opt in args.__dict__:
                if opt == 'command':
                    continue
                if args.__dict__[opt] is not parser.get_default(opt):
                    if opt not in accepted:
                        sys.stderr.write("Warning: option '{0}' is ignored for this command.\n".format(opt))
            cmd['command'](**values)
    except Exception as e:
        sys.stderr.write('Error occured: {0}\n'.format(str(e)))
        sys.exit(-2)
