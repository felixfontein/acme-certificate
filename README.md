# acme-certificate

Allows to obtain certificates from Let's Encrypt with minimal interaction with the webserver. Most code is executed on the controller, and the account key is never send to the nodes.

## Description

This is an [Ansible](https://github.com/ansible/ansible) role which can use any CA supporting the ACME protocol, such as [Let's Encrypt](https://letsencrypt.org/), to issue TLS/SSL certificates for your server. This role requires Ansible 2.5.1 or newer and is based on the new [letsencrypt module](https://docs.ansible.com/ansible/latest/letsencrypt_module.html) coming with Ansible.

(If you prefer the [acme_compact](https://github.com/felixfontein/acme-compact) based version, you can check out the [acme_compact_version branch](https://github.com/felixfontein/acme-certificate/tree/acme_compact_version).)

The main advantage of this approach over others is that *almost no code is executed on your webserver*: only when you use HTTP challenges, files need to be copied onto your webserver, and afterwards deleted from it. Everything else is executed on your local machine!

(This does not cover installing the certificates, you have to do that yourself in another role.)

The role uses a Python script (`certtool.py`) for convenience tasks with certificates, like creating account keys and Certificate Sign Requests (CSRs).

## Requirements

Requires `openssl` installed on the controller. It must be available on the executable path.

If DNS challenges are used, there can be other requirements depending on the DNS provider. For example, for Amazon's Route 53, the Ansible `route53` module requires the Python `boto` package.

## Role Variables

These are the main variables:

- `acme_account`: Path to the private ACME account key. Can be created by running `python code/certtool.py gen-account-key --account-key ../../keys/acme-account.key`. Must always be specified.
- `acme_email`: Your email address which shall be associated to the ACME account. Must always be specified.
- `algorithm`: The algorithm used for creating private keys. The default is `"rsa"`; other choices are `"p-256"`, `"p-384"` or `"p-521"` for the NIST elliptic curves `prime256v1`, `secp384r1` and `secp521r1`, respectively.
- `key_length`: The bitlength to use for RSA private keys. The default is 4096.
- `key_name`: The basename for storing the keys and certificates. The default is the first domain specified, with `*` replaced by `_`.
- `keys_path`: Where the keys and certificates are stored. Default value is `"keys/"`.
- `keys_old_path`: Where old keys and certificates should be copied to; used in case `keys_old_store` is true. Default value is `"keys/old/"`.
- `keys_old_store`: If set to `true`, will make copies of old keys and certificates. The copies will be stored in the directory specified by `keys_old_store`. Default value is `false`.
- `keys_old_prepend_timestamp`: Whether copies of old keys and certificates should be prepended by the current date and time. Default value is `false`.
- `ocsp_must_staple`: Whether a certificate with the OCSP Must Staple extension is requested. Default value is `false`.
- `agreement`: The terms of service document the user agrees to. Default value is `https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf`.
- `acme_directory`: The ACME directory to use. Default is `https://acme-v02.api.letsencrypt.org/directory`, which is the current production ACME v2 endpoint of Let's Encrypt.
- `acme_version`: The ACME directory's version. Default is 2. Use 1 for ACME v1.
- `challenge`: The challenge type to use. Should be `http-01` for HTTP challenges (needs access to web server) or `dns-01` for DNS challenges (needs access to DNS provider).
- `root_certificate`: The root certificate for the ACME directory. Default value is `https://letsencrypt.org/certs/isrgrootx1.pem` for the root certificate of Let's Encrypt.

### HTTP Challenges

For HTTP challenges, the following variables define how the challenges can be put onto the (remote) webserver:

- `server_location`: Location where `.well-known/acme-challenge/` will be served from. Default is `/var/www/challenges`.
- `http_become`: Argument for `become:` for the `file` and `copy` tasks. Default value is `false`.
- `http_challenge_user`: The user the challenge files are owned by. Default value is `root`.
- `http_challenge_group`: The group the challenge files are owned by. Default value is `http`.
- `http_challenge_folder_mode`: The mode to use for the challenge folder. Default value is `0750` (octal).
- `http_challenge_file_mode`: The mode to use for the challenge files. Default value is `0640` (octal).

The following subsection shows how to configure [nginx](https://nginx.org/) for HTTP challenges. Configuring other webservers can be done in a similar way.

#### Nginx configuration

Assume that for one of your TLS/SSL protected domains, you use a HTTP-to-HTTPS redirect. Let's assume it looks like this:

    server {
        listen       example.com:80;
        server_name  example.com *.example.com;
        return 301   https://www.example.com$request_uri;
    }

To allow the `acme-certificate` role to put something at `http://*.example.com/.well-known/acme-challenge/`, you can change this to:

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

With this nginx config, all other URLs on `*.example.com` and `example.com` are still redirected, while everything in `*.example.com/.well-known/acme-challenge/` is served from `/var/www/challenges`. When adjusting the location of `/var/www/challenges`, you must also change `server_location`.

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

- `dns_provider`: must be one of `route53`, `hosttech` or `gcdns`. Each needs more information:
  - For `route53` (Amazon Route 53), the credentials must be passed as `aws_access_key` and `aws_secret_key`.
  - For `hosttech` (hosttech GmbH, requires external [hosttech_dns_record module](https://github.com/felixfontein/ansible-hosttech)).
  - For `gcdns` (Google Cloud DNS), the files `tasks/dns-gcdns-*.yml` need to be adjusted to add required credentials. See the documentation of the [gcdns_record module](https://docs.ansible.com/ansible/latest/gcdns_record_module.html).

Please note that the DNS challenge code is experimental. The Route 53 and Hosttech functionality has been tested. Also, the code tries to extract the DNS zone from the domain by taking the last two components separated by dots. This will fail for example for `.co.uk` domains or other nested zones.

Support for more DNS providers can be added by adding `tasks/dns-NAME-create.yml` and `tasks/dns-NAME-cleanup.yml` files with similar content as in the existing files. Ansible modules of interest are [azure_rm_dnsrecordset](https://docs.ansible.com/ansible/latest/azure_rm_dnsrecordset_module.html) for Azure, [os_recordset](https://docs.ansible.com/ansible/latest/os_recordset_module.html) for OpenStack, [rax_dns_record](https://docs.ansible.com/ansible/latest/rax_dns_record_module.html) for RackSpace, and [udm_dns_record](https://docs.ansible.com/ansible/latest/udm_dns_record_module.html) for univention corporate servers (UCS).

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
      copy: src=keys/{{ item }} dest=/etc/ssl/private/ owner=root group=root mode=0400
      with_items:
      - www.example.com.key
      notify: reload webserver

    - name: copy certificates
      copy: src=keys/{{ item }} dest=/etc/ssl/server-certs/ owner=root group=root mode=0444
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
        acme_account: 'keys/acme-account.key'
        acme_email: 'mail@example.com'
        # For HTTP challenges:
        server_location: '/var/www/challenges/'
        http_challenge_user: root
        http_challenge_group: http
        http_challenge_folder_mode: "0750"
        http_challenge_file_mode: "0640"
        # For DNS challenges:
        dns_provider: route53
        aws_access_key: REPLACE_WITH_YOUR_ACCESS_KEY
        aws_secret_key: REPLACE_WITH_YOUR_SECRET_KEY
      roles:
        - role: acme-certificate
          domains: ['example.com', 'www.example.com']
          # Use DNS challenges:
          challenge: dns-01
          # The certificate files will be stored at:
          #    keys/example.com.key  (private key)
          #    keys/example.com.csr  (certificate signing request)
          #    keys/example.com.pem  (certificate)
          #    keys/example.com.cnf  (OpenSSL config for CSR creation -- can be safely deleted)
          #    keys/example.com-chain.pem  (intermediate certificate)
          #    keys/example.com-fullchain.pem  (certificate with intermediate certificate)
          #    keys/example.com-root.pem  (root certificate)
          #    keys/example.com-rootchain.pem  (intermediate certificate with root certificate)
        - role: acme-certificate
          domains: ['another.example.com']
          key_name: 'another.example.com-rsa'
          key_length: 4096
          # Use HTTP challenges:
          challenge: http-01
          # The certificate files will be stored at:
          #    keys/another.example.com-rsa.key  (private key)
          #    keys/another.example.com-rsa.csr  (certificate signing request)
          #    keys/another.example.com-rsa.pem  (certificate)
          #    keys/another.example.com-rsa.cnf  (OpenSSL config for CSR creation -- can be safely deleted)
          #    keys/another.example.com-rsa-chain.pem  (intermediate certificate)
          #    keys/another.example.com-rsa-fullchain.pem  (certificate with intermediate certificate)
          #    keys/another.example.com-rsa-root.pem  (root certificate)
          #    keys/another.example.com-rsa-rootchain.pem  (intermediate certificate with root certificate)
        - role: acme-certificate
          domains: ['another.example.com']
          key_name: 'another.example.com-ecc'
          algorithm: 'p-256'
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

Copyright (c) 2018 Felix Fontein

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
