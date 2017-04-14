#!/usr/bin/env python
"""Command line interface for the compact ACME library."""

import acme_lib
import argparse
import sys
import textwrap


def _gen_account_key(account_key, key_length, algorithm):
    key = acme_lib.create_key(key_length=key_length, algorithm=algorithm)
    acme_lib.write_file(account_key, key)


def _gen_cert_key(key, key_length, algorithm):
    the_key = acme_lib.create_key(key_length=key_length, algorithm=algorithm)
    acme_lib.write_file(key, the_key)


def _gen_csr(domains, key, csr, must_staple):
    if csr.endswith('.csr'):
        config_filename = csr[:-4] + '.cnf'
    else:
        config_filename = csr + '.cnf'
    sys.stderr.write('Writing OpenSSL config to {0}.\n'.format(config_filename))
    the_csr = acme_lib.generate_csr(key, config_filename, domains.split(','), must_staple=must_staple)
    acme_lib.write_file(csr, the_csr)


def _print_csr(csr):
    sys.stdout.write(acme_lib.get_csr_as_text(csr) + '\n')


def _get_root(root_url, cert):
    ic = acme_lib.download_certificate(root_url)
    if cert is None:
        sys.stdout.write(ic + '\n')
    else:
        acme_lib.write_file(cert, ic + '\n')
        sys.stderr.write("Stored root certificate at '{0}'.\n".format(cert))


def _get_intermediate(intermediate_url, cert):
    ic = acme_lib.download_certificate(intermediate_url)
    if cert is None:
        sys.stdout.write(ic + '\n')
    else:
        acme_lib.write_file(cert, ic + '\n')
        sys.stderr.write("Stored intermediate certificate at '{0}'.\n".format(cert))


def _get_certificate(account_key, csr, acme_dir, CA, cert, email):
    sys.stderr.write("Preparing challenges...")
    state = acme_lib.get_challenges(account_key, csr, CA, email_address=email)
    sys.stderr.write(" ok\n")
    try:
        sys.stderr.write("Writing and verifying challenges...")
        acme_lib.write_challenges(state, acme_dir)
        acme_lib.verify_challenges(state)
        sys.stderr.write(" ok\n")
        sys.stderr.write("Notifying CA of challenges...")
        acme_lib.notify_challenges(state)
        sys.stderr.write(" ok\n")
        sys.stderr.write("Verifying domains...\n")
        result = acme_lib.check_challenges(state, csr, lambda domain: sys.stderr.write("Verified domain {0}!\n".format(domain)))
        sys.stderr.write("Certificate is signed!\n")
        if cert is None:
            sys.stdout.write(result)
        else:
            acme_lib.write_file(cert, result)
            sys.stderr.write("Stored certificate at '{0}'.\n".format(cert))
    finally:
        acme_lib.remove_challenges(state, acme_dir)


def _get_certificate_part1(statefile, account_key, csr, acme_dir, CA, email):
    sys.stderr.write("Preparing challenges...")
    state = acme_lib.get_challenges(account_key, csr, CA, email_address=email)
    sys.stderr.write(" ok\n")
    sys.stderr.write("Writing challenges...")
    acme_lib.write_challenges(state, acme_dir)
    sys.stderr.write(" ok\n")
    sys.stderr.write("Serializing state...")
    with open(statefile, "w") as sf:
        sf.write(acme_lib.serialize_state(state))
    sys.stderr.write(" ok\n")


def _get_certificate_part2(statefile, csr, cert):
    sys.stderr.write("Deserializing state...")
    with open(statefile, "r") as sf:
        state = acme_lib.deserialize_state(sf.read())
    sys.stderr.write(" ok\n")
    sys.stderr.write("Verifying challenges...")
    acme_lib.verify_challenges(state)
    sys.stderr.write(" ok\n")
    sys.stderr.write("Notifying CA of challenges...")
    acme_lib.notify_challenges(state)
    sys.stderr.write(" ok\n")
    sys.stderr.write("Verifying domains...\n")
    result = acme_lib.check_challenges(state, csr, lambda domain: sys.stderr.write("Verified domain {0}!\n".format(domain)))
    sys.stderr.write("Certificate is signed!\n")
    if cert is None:
        sys.stdout.write(result)
    else:
        acme_lib.write_file(cert, result)
        sys.stderr.write("Stored certificate at '{0}'.\n".format(cert))


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=textwrap.dedent("""\
                This script automates the process of getting a signed TLS certificate from
                Let's Encrypt using the ACME protocol. It can both be run from the server
                and from another machine (when splitting the process up in two steps).
                The script needs to have access to your private account key, so PLEASE READ
                THROUGH IT! It's only 265+569 lines (including docstrings), so it won't
                take too long.

                ===Example Usage: Creating Letsencrypt account key, private key for certificate and CSR===
                python acme_compact.py gen-account-key --account-key /path/to/account.key
                python acme_compact.py gen-key --key /path/to/domain.key
                python acme_compact.py gen-csr --key /path/to/domain.key --csr /path/to/domain.csr --domains example.com,www.example.com
                ===================
                Note that the email address does not have to be specified.

                Also note that by default, RSA keys are generated. If you want ECC keys,
                please specify "--algorithm <alg>" with <alg> being "p-256" or "p-384".

                ===Example Usage: Creating certifiate from CSR on server===
                python acme_compact.py get-certificate --account-key /path/to/account.key --email mail@example.com --csr /path/to/domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ --cert /path/to/signed.crt 2>> /var/log/acme_compact.log
                ===================

                ===Example Usage: Creating certifiate from CSR from another machine===
                python acme_compact.py get-certificate-part-1 --account-key /path/to/account.key --email mail@example.com --csr /path/to/domain.csr --statefile /path/to/state.json --acme-dir /tmp/acme-challenge/ 2>> /var/log/acme_compact.log
                ... copy files from /tmp/acme-challenge/ into /usr/share/nginx/html/.well-known/acme-challenge/ on the web server ...
                python acme_compact.py get-certificate-part-2 --csr /path/to/domain.csr --statefile /path/to/state.json --cert /path/to/signed.crt 2>> /var/log/acme_compact.log
                ===================

                ===Example Usage: Combining signed certificate with intermediate certificate===
                python acme_compact.py get-intermediate --cert /path/to/domain-intermediate.crt
                cat /path/to/signed.crt /path/to/domain-intermediate.crt > /path/to/signed-with-intermediate.crt
                ===================
                """)
        )
        commands = {
            'gen-account-key': {
                'help': 'Generates an account key.',
                'requires': ["account_key"],
                'optional': ["key_length", "algorithm"],
                'command': _gen_account_key,
            },
            'gen-key': {
                'help': 'Generates a certificate key.',
                'requires': ["key"],
                'optional': ["key_length", "algorithm"],
                'command': _gen_cert_key,
            },
            'gen-csr': {
                'help': 'Generates a certificate signing request (CSR). Under *nix, use /dev/stdin after --key to provide key via stdin.',
                'requires': ["domains", "key", "csr"],
                'optional': ["must_staple"],
                'command': _gen_csr,
            },
            'print-csr': {
                'help': 'Prints the given certificate signing request (CSR) in human-readable form.',
                'requires': ["csr"],
                'optional': [],
                'command': _print_csr,
            },
            'get-root': {
                'help': 'Retrieves the root certificate from the CA server and prints it to stdout (if --cert is not specified).',
                'requires': [],
                'optional': ["root_url", "cert"],
                'command': _get_root,
            },
            'get-intermediate': {
                'help': 'Retrieves the intermediate certificate from the CA server and prints it to stdout (if --cert is not specified).',
                'requires': [],
                'optional': ["intermediate_url", "cert"],
                'command': _get_intermediate,
            },
            'get-certificate': {
                'help': 'Given a CSR and an account key, retrieves a certificate and prints it to stdout (if --cert is not specified).',
                'requires': ["account_key", "csr", "acme_dir"],
                'optional': ["CA", "cert", "email"],
                'command': _get_certificate,
            },
            'get-certificate-part-1': {
                'help': 'Given a CSR and an account key, prepares retrieving a certificate. The generated challenge files must be manually uploaded to their respective positions.',
                'requires': ["account_key", "csr", "acme_dir", "statefile"],
                'optional': ["CA", "email"],
                'command': _get_certificate_part1,
            },
            'get-certificate-part-2': {
                'help': 'Assuming that get-certificate-part-1 ran through and the challenges were uploaded, retrieves a certificate and prints it to stdout (if --cert is not specified).',
                'requires': ["csr", "statefile"],
                'optional': ["cert"],
                'command': _get_certificate_part2,
            },
        }
        parser.add_argument("command", type=str, nargs='?', help="must be one of {0}".format(', '.join('"{0}"'.format(command) for command in sorted(commands.keys()))))
        parser.add_argument("--account-key", required=False, help="path to your Let's Encrypt account private key")
        parser.add_argument("--algorithm", required=False, default="rsa", help="the algorithm to use (rsa, ...)")  # FIXME
        parser.add_argument("--key-length", type=int, default=4096, required=False, help="key length for private keys")
        parser.add_argument("--key", required=False, help="path to your certificate's private key")
        parser.add_argument("--csr", required=False, help="path to your certificate signing request")
        parser.add_argument("--acme-dir", required=False, help="path to the .well-known/acme-challenge/ directory")
        parser.add_argument("--CA", required=False, default=None, help="CA to use (default: {0})".format(acme_lib.default_ca))
        parser.add_argument("--use-staging-CA", required=False, default=False, action='store_true', help="Use Let's Encrypt staging CA")
        parser.add_argument("--statefile", required=False, default=None, help="state file for two-part run")
        parser.add_argument("-d", "--domains", required=False, default=None, help="a comma-separated list of domain names")
        parser.add_argument("--cert", required=False, help="file name to store certificate into (otherwise it is printed on stdout)")
        parser.add_argument("--email", required=False, help="email address (will be associated with account)")
        parser.add_argument("--intermediate-url", required=False, default=acme_lib.default_intermediate_url, help="URL for the intermediate certificate (default: {0})".format(acme_lib.default_intermediate_url))
        parser.add_argument("--root-url", required=False, default=acme_lib.default_root_url, help="URL for the root certificate (default: {0})".format(acme_lib.default_root_url))
        parser.add_argument("--must-staple", required=False, default=False, action='store_true', help="request must staple extension for certificate")

        args = parser.parse_args()
        if args.command is None:
            sys.stderr.write("Command must be one of {1}. More information on the available commands:\n\n".format(args.command, ', '.join('"{0}"'.format(command) for command in sorted(commands.keys()))))
            for command in sorted(commands.keys()):
                cmd = commands[command]
                sys.stderr.write('  {0}:\n'.format(command))
                sys.stderr.write('{0}\n'.format(textwrap.indent(cmd['help'], prefix='    ')))
                if cmd['requires']:
                    sys.stderr.write('    Mandatory options: {0}\n'.format(', '.join(['--{0}'.format(opt.replace('_', '-')) for opt in cmd['requires']])))
                if cmd['optional']:
                    sys.stderr.write('    Optional options: {0}\n'.format(', '.join(['--{0}'.format(opt.replace('_', '-')) for opt in cmd['optional']])))
            sys.exit(-1)
        elif args.command not in commands:
            sys.stderr.write("Unknown command '{0}'! Command must be one of {1}.\n".format(args.command, ', '.join('"{0}"'.format(command) for command in sorted(commands.keys()))))
            sys.exit(-1)
        else:
            cmd = commands[args.command]
            accepted = set()
            values = {}
            if args.__dict__['use_staging_CA']:
                if args.__dict__['CA'] is not None:
                    sys.stderr.write("Cannot specify both '--use-staging-CA' and provide '--CA'!\n")
                    sys.exit(-1)
                args.__dict__['CA'] = acme_lib.staging_ca
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
            if 'CA' in values and values['CA'] is None:
                values['CA'] = acme_lib.default_ca
            cmd['command'](**values)
    except Exception as e:
        sys.stderr.write("Error occured: {0}\n".format(str(e)))
        sys.exit(-2)
