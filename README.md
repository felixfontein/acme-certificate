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
To create such a key, run `python roles/letsencrypt/code/acme_compact.py gen-account-key
--account-key keys/letsencrypt-account.key`.

Note that before you can use this role, you *must* adjust the following files to your
server's specific situation:

 * `roles/letsencrypt/issue-certs-copy.yml`
 * `roles/letsencrypt/issue-certs-cleanup.yml`

Please see these files for further instructions and example content.

This code should work with Python 2 (untested) and Python 3, and requires OpenSSL's
command line tool `openssl` in the path. Please note that this project is not well
tested and audited, so please check the code intensively before using this in a
production environment!

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


With this config, you can run `ansible-playbook sample-playbook.yml -t issue-tls-certs` or
`ansible-playbook sample-playbook.yml -t issue-tls-certs-newkey` without any config change,
and you will be issued new or renewed TLS/SSL certificates.
