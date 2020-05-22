# acme_certificate 1.1.1

Allows to obtain certificates from Let's Encrypt with minimal interaction with the webserver. Most code is executed on the controller, and the account key is never send to the nodes.

The role can be installed via [Ansible Galaxy](https://galaxy.ansible.com/felixfontein/acme_certificate):

    ansible-galaxy install felixfontein.acme_certificate

For changes in this role, see [the changelog](CHANGELOG.md).

## Description

This is an [Ansible](https://github.com/ansible/ansible) role which can use any CA supporting the ACME protocol, such as [Let's Encrypt](https://letsencrypt.org/) or [Buypass](https://www.buypass.com/ssl/products/acme), to issue TLS/SSL certificates for your server. This role requires Ansible 2.8.3 or newer and is based on the [acme_certificate module](https://docs.ansible.com/ansible/latest/acme_certificate_module.html) coming with Ansible.

The main advantage of this approach over others is that *almost no code is executed on your webserver*: only when you use HTTP challenges, files need to be copied onto your webserver, and afterwards deleted from it. Everything else is executed on your local machine!

(This does not cover installing the certificates, you have to do that yourself in another role.)

## Requirements

Requires the Python [cryptography](https://pypi.org/project/cryptography/) library installed on the controller, available to the Python version used to execute the playbook. If `cryptography` is not installed, a recent enough version of [PyOpenSSL](https://pypi.org/project/pyOpenSSL/) is currently supported as a fallback by the Ansible `openssl_privatekey` and `openssl_csr` modules.

The `openssl` binary must also be available in the executable path on the controller. It is needed by the `acme_certificate` module in case `cryptography` is not installed, and it is used for certificate chain validation.

If DNS challenges are used, there can be other requirements depending on the DNS provider. For example, for Amazon's Route 53, the Ansible `route53` module requires the Python `boto` package.

## Account Key Setup

You can create an account key using the `openssl` binary as follows:

    # RSA 4096 bit key
    openssl genrsa 4096 -out keys/acme-account.key
    # ECC 256 bit key (P-256)
    openssl ecparam -name prime256v1 -genkey -out keys/acme-account.key
    # ECC 384 bit key (P-384)
    openssl ecparam -name secp384r1 -genkey -out keys/acme-account.key

With Ansible, you can use the `openssl_privatekey` module as follows:

    - name: Generate RSA 4096 key
      openssl_privatekey:
        path: keys/acme-account.key
        type: RSA
        size: 4096
    - name: Generate ECC 256 bit key (P-256)
      openssl_privatekey:
        path: keys/acme-account.key
        type: ECC
        curve: secp256r1
    - name: Generate ECC 384 bit key (P-384)
      openssl_privatekey:
        path: keys/acme-account.key
        type: ECC
        curve: secp384r1

Make sure you store the account key safely. As opposed to certificate private keys, there is no need to regenerate it frequently, and it makes recovation of certificates issued with it very simple.

## Role Variables

Please note that from May 2020 on, all variables must be prefixed with `acme_certificate_`. For some time, the module will still use the old (short) variable names if the longer ones are not defined. Please upgrade your role usage as soon as possible.

These are the main variables:

- `acme_certificate_acme_account`: Path to the private ACME account key. Must always be specified.
- `acme_certificate_acme_email`: Your email address which shall be associated to the ACME account. Must always be specified.
- `acme_certificate_algorithm`: The algorithm used for creating private keys. The default is `"rsa"`; other choices are `"p-256"`, `"p-384"` or `"p-521"` for the NIST elliptic curves `prime256v1`, `secp384r1` and `secp521r1`, respectively.
- `acme_certificate_key_length`: The bitlength to use for RSA private keys. The default is 4096.
- `acme_certificate_key_name`: The basename for storing the keys and certificates. The default is the first domain specified, with `*` replaced by `_`.
- `acme_certificate_keys_path`: Where the keys and certificates are stored. Default value is `"keys/"`.
- `acme_certificate_keys_old_path`: Where old keys and certificates should be copied to; used in case `acme_certificate_keys_old_store` is true. Default value is `"keys/old/"`.
- `acme_certificate_keys_old_store`: If set to `true`, will make copies of old keys and certificates. The copies will be stored in the directory specified by `acme_certificate_keys_old_store`. Default value is `false`.
- `acme_certificate_keys_old_prepend_timestamp`: Whether copies of old keys and certificates should be prepended by the current date and time. Default value is `false`.
- `acme_certificate_ocsp_must_staple`: Whether a certificate with the OCSP Must Staple extension is requested. Default value is `false`.
- `acme_certificate_agreement`: The terms of service document the user agrees to. Default value is `https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf`.
- `acme_certificate_acme_directory`: The ACME directory to use. Default is `https://acme-v02.api.letsencrypt.org/directory`, which is the current production ACME v2 endpoint of Let's Encrypt.
- `acme_certificate_acme_version`: The ACME directory's version. Default is 2. Use 1 for ACME v1.
- `acme_certificate_challenge`: The challenge type to use. Should be `http-01` for HTTP challenges (needs access to web server) or `dns-01` for DNS challenges (needs access to DNS provider).
- `acme_certificate_root_certificate`: The root certificate for the ACME directory. Default value is `https://letsencrypt.org/certs/isrgrootx1.pem` for the root certificate of Let's Encrypt.
- `acme_certificate_deactivate_authzs`: Whether `authz`s (authorizations) should be deactivated afterwards. Default value is `true`. Set to `false` to be able to re-use `authz`s.
- `acme_certificate_modify_account`: Whether the ACME account should be created (if it doesn't exist) and the contact data (email address) should be updated. Default value is `true`. Set to `false` if you want to use the `acme_account` module to manage your ACME account (not done by this role).
- `acme_certificate_privatekey_mode`: Which file mode to use for the private key file. Default value is `"0600"`, which means read- and writeable by the owner, but not accessible by anyone else (except possibly `root`).

### HTTP Challenges

For HTTP challenges, the following variables define how the challenges can be put onto the (remote) webserver:

- `acme_certificate_server_location`: Location where `.well-known/acme-challenge/` will be served from. Default is `/var/www/challenges`.
- `acme_certificate_http_become`: Argument for `become:` for the `file` and `copy` tasks. Default value is `false`.
- `acme_certificate_http_challenge_user`: The user the challenge files are owned by. Default value is `root`.
- `acme_certificate_http_challenge_group`: The group the challenge files are owned by. Default value is `http`.
- `acme_certificate_http_challenge_folder_mode`: The mode to use for the challenge folder. Default value is `0750` (octal).
- `acme_certificate_http_challenge_file_mode`: The mode to use for the challenge files. Default value is `0640` (octal).

The following subsection shows how to configure [nginx](https://nginx.org/) for HTTP challenges. Configuring other webservers can be done in a similar way.

#### Nginx configuration

Assume that for one of your TLS/SSL protected domains, you use a HTTP-to-HTTPS redirect. Let's assume it looks like this:

    server {
        listen       example.com:80;
        server_name  example.com *.example.com;
        return 301   https://www.example.com$request_uri;
    }

To allow the `acme_certificate` role to put something at `http://*.example.com/.well-known/acme-challenge/`, you can change this to:

    server {
        listen       example.com:80;
        server_name  example.com *.example.com;
        location /.well-known/acme-challenge/ {
            alias /var/www/challenges/;
            try_files $uri =404;
        }
        location / {
            return 301   https://www.example.com$request_uri;
        }
    }

With this nginx config, all other URLs on `*.example.com` and `example.com` are still redirected, while everything in `*.example.com/.well-known/acme-challenge/` is served from `/var/www/challenges`. When adjusting the location of `/var/www/challenges`, you must also change `acme_certificate_server_location`.

You can even improve on this by redirecting all URLs in `*.example.com/.well-known/acme-challenge/` which do not resolve to a valid file in `/var/www/challenges` to your HTTPS server as well. One way to do this is:

    server {
        listen       example.com:80;
        server_name  example.com *.example.com;
        location /.well-known/acme-challenge/ {
            alias /var/www/lechallenges/;
            try_files $uri @forward_https;
        }
        location @forward_https {
            return 301   https://www.example.com$request_uri;
        }
        location / {
            return 301   https://www.example.com$request_uri;
        }
    }

With this config, if `/var/www/challenges/` is empty, your HTTP server will behave as if the `/.well-known/acme-challenge/` location isn't specified.

### DNS Challenges

If DNS challenges are used, the following variables define how the challenges can be fulfilled:

- `acme_certificate_dns_provider`: must be one of `route53`, `hosttech`, and `ns1`. Each needs more information:
  - For `route53` (Amazon Route 53), the credentials must be passed as `acme_certificate_aws_access_key` and `acme_certificate_aws_secret_key`.
  - For `hosttech` (hosttech GmbH, requires external [hosttech_dns_record module](https://github.com/felixfontein/ansible-hosttech)).
  - For `ns1` ([ns1.com](https://ns1.com)) the key for your API account must be passed as `acme_certificate_ns1_secret_key`. Also it depends on external module `ns1_record`. Assuming default directory structure and settings, you may need download 2 files into machine where playbook executed:

  ```bash
  curl --create-dirs -L -o ~/.ansible/plugins/module_utils/ns1.py https://github.com/ns1/ns1-ansible-modules/raw/master/module_utils/ns1.py
  curl --create-dirs -L -o ~/.ansible/plugins/modules/ns1_record.py https://github.com/ns1/ns1-ansible-modules/raw/master/library/ns1_record.py
  ```

Please note that the DNS challenge code is not perfect. The Route 53, Hosttech and NS1 functionality has been tested. One thing that is not complete yet is that the code tries to extract the DNS zone from the domain by taking the last two components separated by dots. This will fail for example for `.co.uk` domains or other nested zones.

Support for more DNS providers can be added by adding `tasks/dns-NAME-create.yml` and `tasks/dns-NAME-cleanup.yml` files with similar content as in the existing files.

## Account key conversion

Note that this Ansible role expects the Let's Encrypt account key to be in PEM format and not in JWK format, which is used by the [official Let's Encrypt client certbot](https://github.com/certbot/certbot). If you have created an account key with the official client and now want to use this key with this ansible role, you have to convert it. One tool which can do this is [pem-jwk](https://github.com/dannycoates/pem-jwk).

## Generated Files

Let's assume you created TLS keys for `www.example.com`. You have to copy the relevant files to your webserver. The ansible role created the following files:

  * `keys/www.example.com.key`: this is the private key for the certificate. Ensure nobody can access it.
  * `keys/www.example.com.pem`: this is the certificate itself.
  * `keys/www.example.com-chain.pem`: this is the intermediate certificate(s) needed for a trust path.
  * `keys/www.example.com.cnf`: this is an OpenSSL configuration file used to create the Certificate Signing Request. You can safely delete it.
  * `keys/www.example.com.csr`: this is the Certificate Signing Request used to obtain the certificate. You can safely delete it.
  * `keys/www.example.com-fullchain.pem`: this is the certificate combined with the intermediate certificate(s).
  * `keys/www.example.com-rootchain.pem`: this is the intermediate certificate(s) combined with the root certificate. You might need this for OCSP stapling.
  * `keys/www.example.com-root.pem`: this is the root certificate of Let's Encrypt.

For configuring your webserver, you need the private key (`keys/www.example.com.key`), and either the certificate with intermediate certificate(s) combined in one file (`keys/www.example.com-fullchain.pem`), or the certificate and the intermediate certificate(s) as two separate files (`keys/www.example.com.pem` and `keys/www.example.com-chain.pem`). If you want to use [OCSP stapling](https://en.wikipedia.org/wiki/OCSP_stapling), you will also need `keys/www.example.com-rootchain.pem`.

To get these files onto your web server, you could add tasks as follows:

    - name: copy private keys
      copy:
        src: keys/{{ item }}
        dest: /etc/ssl/private/
        owner: root
        group: root
        mode: "0400"
      with_items:
      - www.example.com.key
      notify: reload webserver

    - name: copy certificates
      copy:
        src: keys/{{ item }}
        dest: /etc/ssl/server-certs/
        owner: root
        group: root
        mode: "0444"
      with_items:
      - www.example.com-rootchain.pem
      - www.example.com-fullchain.pem
      - www.example.com.pem
      notify: reload webserver

The webserver configuration could look as follows (for nginx):

    server {
        listen www.example.com:443 ssl;  # IPv4: listen to IP www.example.com points to
        listen [::]:443 ssl;             # IPv6: listen to localhost
        server_name www.example.com;
        
        # Allowing only TLS 1.0 and 1.2, with a very selective amount of ciphers.
        # According to SSL Lab's SSL server test, this will block:
        #   - Android 2.3.7
        #   - IE 6 and 8 under Windows XP
        #   - Java 6, 7 and 8
        # If that's not acceptable for you, choose other cipher lists. Look for
        # example at https://wiki.mozilla.org/Security/Server_Side_TLS
        ssl_protocols TLSv1.2 TLSv1;
        ssl_prefer_server_ciphers on;
        ssl_ciphers "-ALL !ADH !aNULL !EXP !EXPORT40 !EXPORT56 !RC4 !3DES !eNULL !NULL !DES !MD5 !LOW ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 DHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 DHE-RSA-AES256-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA DHE-RSA-AES256-SHA";
        
        # The certificate chain sent to the browser, as well as the private key.
        # Make sure your private key is only accessible by the webserver during
        # configuration loading (which by default is done with user root).
        ssl_certificate /etc/ssl/server-certs/www.example.com-fullchain.pem;
        ssl_certificate_key /etc/ssl/private/www.example.com.key;
        
        # For OCSP stapling, we need a DNS resolver. Here only public Quad9 and
        # Google DNS servers are specified; I would prepent them by your hoster's
        # DNS servers. You can usually find their IPs in /etc/resolv.conf on your
        # webserver.
        resolver 9.9.9.9 8.8.8.8 8.8.4.4 valid=300s;
        resolver_timeout 10s;
        
        # Enabling OCSP stapling. Nginx will take care of retrieving the OCSP data
        # automatically. See https://wiki.mozilla.org/Security/Server_Side_TLS#OCSP_Stapling
        # for details on OCSP stapling.
        ssl_stapling on;
        ssl_stapling_verify on;
        ssl_trusted_certificate /etc/ssl/server-certs/www.example.com-rootchain.pem;
        
        # Enables a SSL session cache. Adjust the numbers depending on your site's usage.
        ssl_session_cache shared:SSL:50m;
        ssl_session_timeout 30m;
        ssl_session_tickets off;
        
        # You should only use HSTS with proper certificates; the ones from Let's Encrypt
        # are fine for this, self-signed ones are not. See MozillaWiki for more details:
        # https://wiki.mozilla.org/Security/Server_Side_TLS#HSTS:_HTTP_Strict_Transport_Security
        add_header Strict-Transport-Security "max-age=3155760000;";
        
        charset utf-8;
        
        access_log  /var/log/nginx/www.example.com.log combined;
        error_log  /var/log/nginx/www.example.com.log error;
        
        location / {
            root   /var/www/www.example.com;
            index  index.html;
        }
    }

## Dependencies

This role doesn't depend on other roles.

## Example Playbook

This role can be used as follows. Note that it obtains several certificates, and defines variables used for all certificates globally:

    ---
    - name: getting certificates for webserver
      hosts: webserver
      vars:
        acme_certificate_acme_account: 'keys/acme-account.key'
        acme_certificate_acme_email: 'mail@example.com'
        # For HTTP challenges:
        acme_certificate_server_location: '/var/www/challenges/'
        acme_certificate_http_challenge_user: root
        acme_certificate_http_challenge_group: http
        acme_certificate_http_challenge_folder_mode: "0750"
        acme_certificate_http_challenge_file_mode: "0640"
        # For DNS challenges with route53:
        acme_certificate_dns_provider: route53
        acme_certificate_aws_access_key: REPLACE_WITH_YOUR_ACCESS_KEY
        acme_certificate_aws_secret_key: REPLACE_WITH_YOUR_SECRET_KEY
        # For DNS challenges with ns1:
        # acme_certificate_dns_provider: ns1
        # acme_certificate_ns1_secret_key: REPLACE_WITH_YOUR_SECRET_KEY
      roles:
        - role: acme_certificate
          acme_certificate_domains: ['example.com', 'www.example.com']
          # Use DNS challenges:
          acme_certificate_challenge: dns-01
          # The certificate files will be stored at:
          #    keys/example.com.key  (private key)
          #    keys/example.com.csr  (certificate signing request)
          #    keys/example.com.pem  (certificate)
          #    keys/example.com.cnf  (OpenSSL config for CSR creation -- can be safely deleted)
          #    keys/example.com-chain.pem  (intermediate certificate)
          #    keys/example.com-fullchain.pem  (certificate with intermediate certificate)
          #    keys/example.com-root.pem  (root certificate)
          #    keys/example.com-rootchain.pem  (intermediate certificate with root certificate)
        - role: acme_certificate
          acme_certificate_domains: ['another.example.com']
          acme_certificate_key_name: 'another.example.com-rsa'
          acme_certificate_key_length: 4096
          # Use HTTP challenges:
          acme_certificate_challenge: http-01
          # The certificate files will be stored at:
          #    keys/another.example.com-rsa.key  (private key)
          #    keys/another.example.com-rsa.csr  (certificate signing request)
          #    keys/another.example.com-rsa.pem  (certificate)
          #    keys/another.example.com-rsa.cnf  (OpenSSL config for CSR creation -- can be safely deleted)
          #    keys/another.example.com-rsa-chain.pem  (intermediate certificate)
          #    keys/another.example.com-rsa-fullchain.pem  (certificate with intermediate certificate)
          #    keys/another.example.com-rsa-root.pem  (root certificate)
          #    keys/another.example.com-rsa-rootchain.pem  (intermediate certificate with root certificate)
        - role: acme_certificate
          acme_certificate_domains: ['another.example.com']
          acme_certificate_key_name: 'another.example.com-ecc'
          acme_certificate_algorithm: 'p-256'
          # Use HTTP challenges (default for challenge is http-01).
          # The certificate files will be stored at:
          #    keys/another.example.com-ecc.key  (private key)
          #    keys/another.example.com-ecc.csr  (certificate signing request)
          #    keys/another.example.com-ecc.pem  (certificate)
          #    keys/another.example.com-ecc.cnf  (OpenSSL config for CSR creation -- can be safely deleted)
          #    keys/another.example.com-ecc-chain.pem  (intermediate certificate)
          #    keys/another.example.com-ecc-fullchain.pem  (certificate with intermediate certificate)
          #    keys/another.example.com-ecc-root.pem  (root certificate)
          #    keys/another.example.com-ecc-rootchain.pem  (intermediate certificate with root certificate)

## License

The MIT License (MIT)

Copyright (c) 2018-2020 Felix Fontein

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Author Information

The homepage for this role is https://github.com/felixfontein/acme-certificate/. Please use the issue tracker to report problems.
