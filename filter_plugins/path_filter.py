# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os.path


def path_join(list):
    return os.path.join(*list)


class FilterModule(object):
    ''' Ansible core jinja2 filters '''

    def filters(self):
        return {
            'path_join': path_join,
        }
