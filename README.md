# letsencrypt-ansible

This is an [Ansible](https://github.com/ansible/ansible) role which uses
[Let's Encrypt](https://letsencrypt.org/) to issue free TLS/SSL certificates for your
server. This role requires Ansible 2.2 or newer and is based on the new
[letsencrypt module](https://docs.ansible.com/ansible/latest/letsencrypt_module.html)
coming with Ansible.

(If you prefer the [acme_compact](https://github.com/felixfontein/acme-compact) based
version, you can check out the
[acme_compact_version branch](https://github.com/felixfontein/letsencrypt-ansible/tree/acme_compact_version).)

The main advantage of this approach over others is that *almost no code is executed
on your webserver*: only when you use HTTP challenges, files need to be copied onto
your webserver, and afterwards deleted from it. Everything else is executed on your
local machine!

(This does not cover installing the certificates, you have to do that yourself in
another role.)

The role uses a Python script (`certtool.py`) for convenience tasks with certificates,
like creating account keys and Certificate Sign Requests (CSRs).

## Basic Usage

See `sample-playbook.yml` for how to use this role. Please note that it assumes an
account key has already been created (and is available at `keys/letsencrypt-account.key`).
To create such a key, run

    python roles/letsencrypt/code/certtool.py gen-account-key --account-key keys/letsencrypt-account.key

(You can adjust the path `keys/` by setting the variable `keys_path`.)

This code should work with Python 2 and Python 3, and requires OpenSSL's
command line tool `openssl` in the path. Please note that this project is not well
tested and audited, so please check the code intensively before using this in a
production environment!

## Account key conversion

Note that this Ansible role expects the Let's Encrypt account key to be in PEM format
and not in JWK format, which is used by the
[official Let's Encrypt client certbot](https://github.com/letsencrypt/letsencrypt). If
you have created an account key with the official client and now want to use this key
with this ansible role, you have to convert it. One tool which can do this is
[pem-jwk](https://github.com/dannycoates/pem-jwk).

## Integrate this role to your server's playbook

The role supports HTTP and DNS challenges. The type of challenge can be selected
by defining `challenge`. The default value is `http-01` for HTTP challenges.

### HTTP Challenges

In this section I'm assuming you use nginx. Similar setups can be made for other
web servers.

Assume that for one of your TLS/SSL protected domains, you use a HTTP-to-HTTPS
redirect. Let's assume it looks like this:

    server {
        listen       example.com:80;
        server_name  example.com *.example.com;
        return 301   https://www.example.com$request_uri;
    }

To allow the `letsencrypt` role to put something at
`http://*.example.com/.well-known/acme-challenge/`, you can change this to:

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

With this nginx config, all other URLs on `*.example.com` and `example.com` are still redirected,
while everything in `*.example.com/.well-known/acme-challenge/` is served from `/var/www/challenges`.

For this to work, you must set `server_location` to `/var/www/challenges/` in your playbook. You
can adjust the access rights, owner and group of the generated files and folders by defining
`http_challenge_folder_mode`, `http_challenge_file_mode`, `http_challenge_user` and
`http_challenge_group`. Per default, the files are owned by `root` with group `http`, and are
readable only by owner and group.

You can even improve on this by redirecting all URLs in `*.example.com/.well-known/acme-challenge/`
which do not resolve to a valid file in `/var/www/challenges` to your HTTPS server as well. One way
to do this is:

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

With this config, if `/var/www/challenges/` is empty, your HTTP server will behave as if the
`/.well-known/acme-challenge/` location isn't specified.

If you have such a config, you can run `ansible-playbook sample-playbook.yml -t issue-tls-certs`
or `ansible-playbook sample-playbook.yml -t issue-tls-certs-newkey` without any config change,
and you will be issued new or renewed TLS/SSL certificates.

If your setup is differently, you must adjust `roles/letsencrypt/http-*.yml` first. This in
particular applies when you are using different users and/or access rights for your server.

### DNS Challenges

**THIS IS HIGHLY EXPERIMENTAL; USE AT OWN RISK!**

This role now also offers support for DNS challenges. Currently, three DNS providers are supported:

  * Amazon Route 53 (via the built-in [route53 module](http://docs.ansible.com/route53_module.html));
  * Google Cloud DNS (via the built-in [gcdns_record module](https://docs.ansible.com/ansible/latest/gcdns_record_module.html));
  * Hosttech DNS (via the external [hosttech_dns module](https://github.com/felixfontein/ansible-hosttech)).

You can add support for more DNS providers by adding `roles/letsencrypt/dns-PROVIDER-create.yml`
and `roles/letsencrypt/dns-PROVIDER-cleanup.yml` files. Ansible modules of interest are
[azure_rm_dnsrecordset](https://docs.ansible.com/ansible/latest/azure_rm_dnsrecordset_module.html) for Azure,
[os_recordset](https://docs.ansible.com/ansible/latest/os_recordset_module.html) for OpenStack,
[rax_dns_record](https://docs.ansible.com/ansible/latest/rax_dns_record_module.html) for RackSpace, and
[udm_dns_record](https://docs.ansible.com/ansible/latest/udm_dns_record_module.html) for univention corporate servers (UCS).

To use DNS challenges, you need to define more variables:

  * `challenge` must be set to `dns-01`;
  * `dns_provider` must be set to one of `route53`, `gcdns` and `hosttech`;
  * for Route 53, `aws_access_key` and `aws_secret_key` must be set;
  * for Google Cloud DNS, authentication information must be provided by adjusting
    `roles/letsencrypt/tasks/dns-gcdns-*.yml`; note that this has not yet been tested!
  * for Hosttech, `hosttech_username` and `hosttech_password` must be set.

Please note that the DNS challenge code is experimental. The Route 53 and Hosttech functionality
has been tested, but not in a proper production environment.

Also, the code tries to extract the DNS zone from the domain by taking the last two components
separated by dots. This will fail for example for `.co.uk` domains or other nested zones.

## Using the generated files for webserver configuration

Let's assume you created TLS keys for `www.example.com`. You have to copy the relevant files
to your webserver. The ansible role created the following files:

  * `keys/www.example.com.key`: this is the private key for the certificate. Ensure nobody can
    access it.
  * `keys/www.example.com.pem`: this is the certificate itself.
  * `keys/www.example.com-chain.pem`: this is the intermediate certificate(s) needed for a trust
    path.
  * `keys/www.example.com.cnf`: this is an OpenSSL configuration file used to create the
    Certificate Signing Request. You can safely delete it.
  * `keys/www.example.com.csr`: this is the Certificate Signing Request used to obtain the
    certificate. You can safely delete it.
  * `keys/www.example.com-fullchain.pem`: this is the certificate combined with the intermediate
    certificate(s).
  * `keys/www.example.com-rootchain.pem`: this is the intermediate certificate(s) combined with
    the root certificate. You might need this for OCSP stapling.
  * `keys/www.example.com-root.pem`: this is the root certificate of Let's Encrypt.

For configuring your webserver, you need the private key (`keys/www.example.com.key`), and
either the certificate with intermediate certificate(s) combined in one file
(`keys/www.example.com-fullchain.pem`), or the certificate and the intermediate certificate(s)
as two separate files (`keys/www.example.com.pem` and `keys/www.example.com-chain.pem`). If you
want to use [OCSP stapling](https://en.wikipedia.org/wiki/OCSP_stapling), you will also need
`keys/www.example.com-rootchain.pem`.

To get these files onto your web server, you should extend your ansible role for configuring
the webserver to copy them. This could be done as follows:

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
