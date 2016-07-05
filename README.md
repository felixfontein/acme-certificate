# letsencrypt-ansible

This is a template for an [Ansible](https://github.com/ansible/ansible) role which
uses [Let's Encrypt](https://letsencrypt.org/) to issue free TLS/SSL certificates
for your server!

The main advantage of this approach over others is that *almost no code is executed
on your webserver*: you only need to modify this role to automatically put the
challenge on the server (and later remove them). Everything else is executed on your
local machine!

(This does not cover installing them, you have to do that yourself in another role.)

This uses the [acme-compact](https://github.com/felixfontein/acme-compact) library
and command line interface, which is based on Daniel Roesler's
[acme-tiny](https://github.com/diafygi/acme-tiny).

## Basic Usage

See `sample-playbook.yml` for how to use this role. Please note that it assumes an
account key has already been created (and is available at `keys/letsencrypt-account.key`).
To create such a key, run

    python roles/letsencrypt/code/acme_compact.py gen-account-key --account-key keys/letsencrypt-account.key

(You can adjust the path `keys/` by setting the variable `keys_path`.)

Note that before you can use this role, you *must* adjust the following files to your
server's specific situation:

 * `roles/letsencrypt/issue-certs-copy.yml`
 * `roles/letsencrypt/issue-certs-cleanup.yml`

Please see these files for further instructions and example content.

This code should work with Python 2 and Python 3, and requires OpenSSL's
command line tool `openssl` in the path. Please note that this project is not well
tested and audited, so please check the code intensively before using this in a
production environment!

## Account key conversion

Note that this Ansible role expects the Let's Encrypt account key to be in PEM format
and not in JWK format, which is used by the
[official Let's Encrypt client](https://github.com/letsencrypt/letsencrypt). If you
have created an account key with the official client and now want to use this key with
this ansible role, you have to convert it. One tool which can do this is
[pem-jwk](https://github.com/dannycoates/pem-jwk).

## Integrate this role to your server's playbook

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

Then all other URLs on `*.example.com` and `example.com` are still redirected, while everything
in `*.example.com/.well-known/acme-challenge/` is served from `/var/www/challenges`. That's the
place where the example config for the `letsencrypt` role puts all challenges.

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
        
        # For OCSP stapling, we need a DNS resolver. Here only Google DNS servers
        # are specified; I would prepent them by your hoster's DNS servers.
        # You can usually find their IPs in /etc/resolv.conf on your webserver.
        resolver 8.8.8.8 8.8.4.4 valid=300s;
        resolver_timeout 10s;
        
        # Enabling OCSP stapling. Nginx will take care of retrieving the OCSP data
        # automatically. See https://wiki.mozilla.org/Security/Server_Side_TLS#OCSP_Stapling
        # for details on OCSP stapling.
        ssl_stapling on;
        ssl_stapling_verify on;
        ssl_trusted_certificate /etc/ssl/server-certs/www.example.com-rootchain.pem;
        
        # Enables a SSL session cache. Adjust the numbers depending on your site's usage.
        ssl_session_cache shared:SSL:50m;
        ssl_session_timeout 5m;
        
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
