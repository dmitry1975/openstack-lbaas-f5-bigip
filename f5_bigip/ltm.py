# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Gap Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import logging

from balancer.drivers import base_driver
from balancer.db import api as db_api

from . import pycontrol


LOG = logging.getLogger(__name__)


def pool_name(sf_ref):
    return "pool_%s" % (sf_ref['id'],)


def vip_name(vip_ref):
    return "virtual_%s" % (vip_ref['id'],)


def probe_name(probe_ref):
    return "monitor_%s" % (probe_ref['id'],)


def sticky_name(sticky_ref):
    return "sticky_%s" % (sticky_ref['id'],)


class Driver(base_driver.BaseDriver):
    WSDLS = ['LocalLB.Pool', 'LocalLB.PoolMember', 'LocalLB.VirtualServer',
             'LocalLB.Monitor', 'LocalLB.ProfilePersistence']

    def __init__(self, conf, device_ref):
        super(Driver, self).__init__(conf, device_ref)
        self.client = pycontrol.BIGIP(hostname=device_ref['ip'],
                                      port=device_ref['port'],
                                      username=device_ref['user'],
                                      password=device_ref['password'],
                                      fromurl=True, wsdls=self.WSDLS)

    def create_server_farm(self, sf_ref, predictors):
        LOG.debug("Called create_server_farm(), sf_ref: %s, predictors: %s",
                  sf_ref, predictors)
        method = self._get_methods()[predictors[0]['type']]
        members = self.client.LocalLB.Pool.typefactory.create(
                          'Common.IPPortDefinitionSequence')
        self.client.LocalLB.Pool.create(pool_names=[pool_name(sf_ref)],
                                        lb_methods=[method],
                                        members=[members])
        LOG.debug("Ended create_server_farm(), sf_ref: %r, predictors: %r",
                  sf_ref, predictors)

    def delete_server_farm(self, sf_ref):
        LOG.debug("Called delete_server_farm(), sf_ref: %r", sf_ref)
        self.client.LocalLB.Pool.delete_pool(pool_names=[pool_name(sf_ref)])
        LOG.debug("Ended delete_server_farm(), sf_ref: %r", sf_ref)

    def create_real_server(self, server_ref):
        LOG.debug("Called create_real_server(), server_ref: %r", server_ref)

    def delete_real_server(self, server_ref):
        LOG.debug("Called delete_real_server(), server_ref: %r", server_ref)

    def add_real_server_to_server_farm(self, sf_ref, server_ref):
        LOG.debug("Called add_real_server_to_server_farm(), sf_ref: %r, "
                  "server_ref: %r", sf_ref, server_ref)
        members = self.client.LocalLB.Pool.typefactory.create(
                          'Common.IPPortDefinitionSequence')
        members.item = [self._define_member(server_ref)]
        self.client.LocalLB.Pool.add_member_v2(pool_names=[pool_name(sf_ref)],
                                               members=[members])
        try:
            condition = server_ref['extra']['condition']
        except (KeyError, TypeError):
            pass
        else:
            if condition.upper() == 'DISABLED':
                self.suspend_real_server(sf_ref, server_ref)
        self._member_set_ratio(sf_ref, server_ref)
        self._member_set_dynamic_ratio(sf_ref, server_ref)
        LOG.debug("Ended add_real_server_to_server_farm(), sf_ref: %r, "
                  "server_ref: %r", sf_ref, server_ref)

    def _member_set_ratio(self, sf_ref, server_ref):
        ratios = self.client.LocalLB.PoolMember.typefactory.create(
                        'LocalLB.PoolMember.MemberRatioSequence')
        ratios.item = [self._define_member_ratio(server_ref)]
        self.client.LocalLB.PoolMember.set_ratio(
            pool_names=[pool_name(sf_ref)],
            ratios=[ratios])

    def _define_member_ratio(self, server_ref):
        ratio = self.client.LocalLB.PoolMember.typefactory.create(
                        'LocalLB.PoolMember.MemberRatio')
        ratio.member = self._define_member(server_ref)
        ratio.ratio = server_ref['weight']
        return ratio

    def _member_set_dynamic_ratio(self, sf_ref, server_ref):
        ratios = self.client.LocalLB.PoolMember.typefactory.create(
                        'LocalLB.PoolMember.MemberDynamicRatioSequence')
        ratios.item = [self._define_member_dynamic_ratio(server_ref)]
        self.client.LocalLB.PoolMember.set_dynamic_ratio(
            pool_names=[pool_name(sf_ref)],
            dynamic_ratios=[ratios])

    def _define_member_dynamic_ratio(self, server_ref):
        ratio = self.client.LocalLB.PoolMember.typefactory.create(
                        'LocalLB.PoolMember.MemberDynamicRatio')
        ratio.member = self._define_member(server_ref)
        try:
            dynamic_ratio = server_ref['extra']['dynamic-ratio']
        except (KeyError, TypeError):
            dynamic_ratio = 1
        ratio.dynamic_ratio = dynamic_ratio
        return ratio

    def delete_real_server_from_server_farm(self, sf_ref, server_ref):
        LOG.debug("Called delete_real_server_from_server_farm(), sf_ref: %r, "
                  "server_ref: %r", sf_ref, server_ref)
        members = self.client.LocalLB.Pool.typefactory.create(
                          'Common.IPPortDefinitionSequence')
        members.item = [self._define_member(server_ref)]
        self.client.LocalLB.Pool.remove_member(pool_names=[pool_name(sf_ref)],
                                               members=[members])
        LOG.debug("Ended delete_real_server_from_server_farm(), sf_ref: %r, "
                  "server_ref: %r", sf_ref, server_ref)

    def activate_real_server(self, sf_ref, server_ref):
        LOG.debug("Called activate_real_server(), sf_ref: %r, server_ref: %r",
                  sf_ref, server_ref)
        state = self.client.LocalLB.Pool.typefactory.\
                            create('Common.EnabledState')
        self._set_member_session_state(state.STATE_ENABLED,
                                       self._define_member(server_ref),
                                       pool_name(sf_ref))
        LOG.debug("Ended activate_real_server(), sf_ref: %r, server_ref: %r",
                  sf_ref, server_ref)

    def suspend_real_server(self, sf_ref, server_ref):
        LOG.debug("Called suspend_real_server(), sf_ref: %r, server_ref: %r",
                  sf_ref, server_ref)
        state = self.client.LocalLB.Pool.typefactory.\
                            create('Common.EnabledState')
        self._set_member_session_state(state.STATE_DISABLED,
                                       self._define_member(server_ref),
                                       pool_name(sf_ref))
        LOG.debug("Ended suspend_real_server(), sf_ref: %r, server_ref: %r",
                  sf_ref, server_ref)

    def _set_member_session_state(self, state, member, pool_name):
        states = self.client.LocalLB.PoolMember.typefactory.\
                                     create('LocalLB.PoolMember.'
                                            'MemberSessionStateSequence')
        states.item = [self._define_member_state(state, member)]
        self.client.LocalLB.PoolMember.set_session_enabled_state(
                pool_names=[pool_name],
                session_states=[states])

    def create_virtual_ip(self, vip_ref, sf_ref):
        LOG.debug("Called create_virtual_ip(), vip_ref: %r, sf_ref: %r",
                  vip_ref, sf_ref)
        vservers = self.client.LocalLB.VirtualServer.typefactory.create(
                           'Common.VirtualServerSequence')
        vservers.item = [self._define_vserver(vip_ref)]
        profiles = self.client.LocalLB.VirtualServer.typefactory.\
                               create('LocalLB.VirtualServer.'
                                      'VirtualServerProfileSequence')
        profiles.item = [self._define_tcp_profile()]
        protocol = vip_ref['extra']['protocol']
        if protocol == 'HTTP':
            profiles.item.append(self._define_http_profile())
        resources = self.client.LocalLB.VirtualServer.typefactory.\
                                create('LocalLB.VirtualServer.'
                                       'VirtualServerResourceSequence')
        resources.item = [self._define_vserver_resource(sf_ref)]
        self.client.LocalLB.VirtualServer.create(definitions=vservers,
                                                 wildmasks=[vip_ref['mask']],
                                                 resources=resources,
                                                 profiles=[profiles])
        self.client.LocalLB.VirtualServer.\
                    set_snat_automap(virtual_servers=[vip_name(vip_ref)])
        stickies = db_api.sticky_get_all_by_sf_id(self.conf, sf_ref['id'])
        for sticky_ref in stickies:
            self._add_persistence_profile(sticky_name(sticky_ref), vip_ref)
        LOG.debug("Ended create_virtual_ip(), vip_ref: %r, sf_ref: %r",
                  vip_ref, sf_ref)

    def delete_virtual_ip(self, vip_ref):
        LOG.debug("Called delete_virtual_ip(), vip_ref: %r", vip_ref)
        self.client.LocalLB.VirtualServer.\
                    delete_virtual_server(virtual_servers=[vip_name(vip_ref)])
        LOG.debug("Ended delete_virtual_ip(), vip_ref: %r", vip_ref)

    def _define_http_profile(self):
        profile = self.client.LocalLB.VirtualServer.typefactory.\
                              create('LocalLB.VirtualServer.'
                                     'VirtualServerProfile')
        profile.profile_name = 'http'
        return profile

    def _define_tcp_profile(self):
        context = self.client.LocalLB.VirtualServer.typefactory.\
                              create('LocalLB.ProfileContextType')
        profile = self.client.LocalLB.VirtualServer.typefactory.\
                              create('LocalLB.VirtualServer.'
                                     'VirtualServerProfile')
        profile.profile_context = context.PROFILE_CONTEXT_TYPE_ALL
        profile.profile_name = 'tcp'
        return profile

    def _define_vserver_resource(self, sf_ref):
        type = self.client.LocalLB.VirtualServer.typefactory.\
                           create('LocalLB.VirtualServer.VirtualServerType')
        resource = self.client.LocalLB.VirtualServer.typefactory.\
                               create('LocalLB.VirtualServer.'
                                      'VirtualServerResource')
        resource.type = type.RESOURCE_TYPE_POOL
        resource.default_pool_name = pool_name(sf_ref)
        return resource

    def _define_vserver(self, vip_ref):
        protocol = self.client.LocalLB.VirtualServer.typefactory.create(
                       'Common.ProtocolType')
        vserver = self.client.LocalLB.VirtualServer.typefactory.create(
                          'Common.VirtualServerDefinition')
        vserver.name = vip_name(vip_ref)
        vserver.address = vip_ref['address']
        vserver.port = vip_ref['port']
        vserver.protocol = protocol.PROTOCOL_TCP
        return vserver

    def _define_member(self, server_ref):
        member = self.client.LocalLB.Pool.typefactory.create(
                         'Common.IPPortDefinition')
        member.address = server_ref['address']
        member.port = server_ref['port']
        return member

    def _define_member_state(self, state, member):
        member_state = self.client.LocalLB.PoolMember.typefactory.\
                                   create('LocalLB.PoolMember.'
                                          'MemberSessionState')
        member_state.member = member
        member_state.session_state = state
        return member_state

    def create_probe(self, probe_ref):
        LOG.debug("Called create_probe(), probe_ref: %r", probe_ref)
        template = self.client.LocalLB.Monitor.typefactory.\
                               create('LocalLB.Monitor.MonitorTemplate')
        type = self.client.LocalLB.Monitor.typefactory.\
                           create('LocalLB.Monitor.TemplateType')
        template.template_name = probe_name(probe_ref)
        probe_type = probe_ref['type'].upper()
        if probe_type == 'HTTP':
            template.template_type = type.TTYPE_HTTP
            self._create_http_monitor_template(template, probe_ref)
        elif probe_type == 'TCP_HALF_OPEN':
            template.template_type = type.TTYPE_TCP_HALF_OPEN
            self._create_tcp_half_monitor_template(template, probe_ref)
        LOG.debug("Ended create_probe(), probe_ref: %r", probe_ref)

    def _create_http_monitor_template(self, template, probe_ref):
        probe_extra = probe_ref['extra'] or {}
        type = self.client.LocalLB.Monitor.typefactory.\
                           create('LocalLB.AddressType')
        attrs = self.client.LocalLB.Monitor.typefactory.\
                            create('LocalLB.Monitor.CommonAttributes')
        attrs.parent_template = 'http'
        attrs.is_read_only = False
        attrs.is_directly_usable = True
        attrs.interval = probe_extra.get('interval', 5)
        attrs.timeout = probe_extra.get('timeout', (attrs.interval * 3 + 1))
        attrs.dest_ipport.address_type = type.ATYPE_STAR_ADDRESS_STAR_PORT
        attrs.dest_ipport.ipport.address = '0.0.0.0'
        attrs.dest_ipport.ipport.port = 0
        self.client.LocalLB.Monitor.\
                    create_template(templates=[template],
                                    template_attributes=[attrs])
        if probe_extra:
            value_type = self.client.LocalLB.Monitor.typefactory.\
                                     create('LocalLB.Monitor.'
                                            'StrPropertyType')
            send = probe_extra.get('send')
            recv = probe_extra.get('recv')
            values = []
            if send:
                values.append(self._define_str_value(send,
                                                     value_type.STYPE_SEND))
            if recv:
                values.append(self._define_str_value(recv,
                                                     value_type.STYPE_RECEIVE))
            if values:
                template_names = [probe_name(probe_ref)] * len(values)
                self.client.LocalLB.Monitor.set_template_string_property(
                        template_names=template_names,
                        values=values)

    def _create_tcp_half_monitor_template(self, template, probe_ref):
        probe_extra = probe_ref['extra'] or {}
        type = self.client.LocalLB.Monitor.typefactory.\
                           create('LocalLB.AddressType')
        attrs = self.client.LocalLB.Monitor.typefactory.\
                            create('LocalLB.Monitor.CommonAttributes')
        attrs.parent_template = 'tcp_half_open'
        attrs.is_read_only = False
        attrs.is_directly_usable = True
        attrs.interval = probe_extra.get('interval', 5)
        attrs.timeout = probe_extra.get('timeout', (attrs.interval * 3 + 1))
        attrs.dest_ipport.address_type = type.ATYPE_STAR_ADDRESS_STAR_PORT
        attrs.dest_ipport.ipport.address = '0.0.0.0'
        attrs.dest_ipport.ipport.port = 0
        self.client.LocalLB.Monitor.\
                    create_template(templates=[template],
                                    template_attributes=[attrs])

    def _define_str_value(self, value, type):
        str_value = self.client.LocalLB.Monitor.typefactory.\
                                create('LocalLB.Monitor.StringValue')
        str_value.type.value = type
        str_value.value = value
        return str_value

    def delete_probe(self, probe_ref):
        LOG.debug("Called delete_probe(), probe: %r", probe_ref)
        self.client.LocalLB.Monitor.delete_template(
                template_names=[probe_name(probe_ref)])
        LOG.debug("Ended delete_probe(), probe: %r", probe_ref)

    def add_probe_to_server_farm(self, sf_ref, probe_ref):
        LOG.debug("Called add_probe_to_server_farm(), sf: %r, probe: %s",
                  sf_ref, probe_ref)
        assoc = self.client.LocalLB.Pool.\
                     get_monitor_association(pool_names=[pool_name(sf_ref)])[0]
        type = self.client.LocalLB.Pool.typefactory.\
                                   create('LocalLB.MonitorRuleType')
        if assoc.monitor_rule.type in (type.MONITOR_RULE_TYPE_NONE,
                                       type.MONITOR_RULE_TYPE_UNDEFINED):
            assoc.monitor_rule.type = type.MONITOR_RULE_TYPE_SINGLE
            assoc.monitor_rule.monitor_templates = [probe_name(probe_ref)]
        elif assoc.monitor_rule.type == type.MONITOR_RULE_TYPE_SINGLE:
            if assoc.monitor_rule.monitor_templates == ['/Common/none']:
                assoc.monitor_rule.type = type.MONITOR_RULE_TYPE_SINGLE
                assoc.monitor_rule.monitor_templates = [probe_name(probe_ref)]
            else:
                assoc.monitor_rule.type = type.MONITOR_RULE_TYPE_AND_LIST
                assoc.monitor_rule.monitor_templates.append(
                        probe_name(probe_ref))
        else:
            assoc.monitor_rule.monitor_templates.append(probe_name(probe_ref))
        self.client.LocalLB.Pool.\
                    set_monitor_association(monitor_associations=[assoc])
        LOG.debug("Ended add_probe_to_server_farm(), sf: %r, probe: %s",
                  sf_ref, probe_ref)

    def delete_probe_from_server_farm(self, sf_ref, probe_ref):
        def template_filter(name):
            return not (name.endswith("/%s" % (probe_name(probe_ref),)) or
                        name == '/Common/none')

        LOG.debug("Called delete_probe_from_server_farm(), sf: %r, probe: %s",
                  sf_ref, probe_ref)
        assoc = self.client.LocalLB.Pool.\
                     get_monitor_association(pool_names=[pool_name(sf_ref)])[0]
        type = self.client.LocalLB.Pool.typefactory.\
                                   create('LocalLB.MonitorRuleType')
        if assoc.monitor_rule.type in (type.MONITOR_RULE_TYPE_SINGLE,
                                       type.MONITOR_RULE_TYPE_AND_LIST):
            assoc.monitor_rule.monitor_templates = \
                filter(template_filter, assoc.monitor_rule.monitor_templates)
            if not assoc.monitor_rule.monitor_templates:
                assoc.monitor_rule.type = type.MONITOR_RULE_TYPE_NONE
            elif len(assoc.monitor_rule.monitor_templates) == 1:
                assoc.monitor_rule.type = type.MONITOR_RULE_TYPE_SINGLE
            else:
                assoc.monitor_rule.type = type.MONITOR_RULE_TYPE_AND_LIST
            self.client.LocalLB.Pool.\
                        set_monitor_association(monitor_associations=[assoc])
        LOG.debug("Ended delete_probe_from_server_farm(), sf: %r, probe: %s",
                  sf_ref, probe_ref)

    def create_stickiness(self, sticky_ref):
        LOG.debug("Called create_stickiness(), sticky: %r", sticky_ref)
        if sticky_ref['type'] == 'COOKIE_INSERT':
            self._create_cookie_insert(sticky_ref)
            if sticky_ref['extra']:
                cookie_name = sticky_ref['extra'].get('cookie_name')
                expiration = sticky_ref['extra'].get('expiration')
                if cookie_name:
                    self._set_cookie_name(sticky_name(sticky_ref), cookie_name)
                if expiration:
                    self._set_cookie_expiration(sticky_name(sticky_ref),
                                                expiration)
            vips = db_api.virtualserver_get_all_by_sf_id(self.conf,
                                                         sticky_ref['sf_id'])
            for vip_ref in vips:
                self._add_persistence_profile(sticky_name(sticky_ref), vip_ref)
        LOG.debug("Ended create_stickiness(), sticky: %r", sticky_ref)

    def _add_persistence_profile(self, profile_name, vip_ref):
        profiles = self.client.LocalLB.VirtualServer.typefactory.create(
                'LocalLB.VirtualServer.VirtualServerPersistenceSequence')
        profiles.item = [self._define_persistence(profile_name, default=True)]
        self.client.LocalLB.VirtualServer.add_persistence_profile(
                virtual_servers=[vip_name(vip_ref)],
                profiles=[profiles])

    def _remove_persistence_profile(self, profile_name, vip_ref):
        profiles = self.client.LocalLB.VirtualServer.typefactory.create(
                'LocalLB.VirtualServer.VirtualServerPersistenceSequence')
        profiles.item = [self._define_persistence(profile_name)]
        self.client.LocalLB.VirtualServer.remove_persistence_profile(
                virtual_servers=[vip_name(vip_ref)],
                profiles=[profiles])

    def _define_persistence(self, profile_name, default=False):
        profile = self.client.LocalLB.VirtualServer.typefactory.\
                       create('LocalLB.VirtualServer.VirtualServerPersistence')
        profile.profile_name = profile_name
        profile.default_profile = default
        return profile

    def _create_cookie_insert(self, sticky_ref):
        modes = self.client.LocalLB.ProfilePersistence.typefactory.\
                     create('LocalLB.PersistenceMode')
        self.client.LocalLB.ProfilePersistence.create(
                profile_names=[sticky_name(sticky_ref)],
                modes=[modes.PERSISTENCE_MODE_COOKIE])

    def _set_cookie_name(self, profile_name, cookie_name):
        value = self.client.LocalLB.ProfilePersistence.typefactory.\
                     create('LocalLB.ProfileString')
        value.value = cookie_name
        value.default_flag = False
        self.client.LocalLB.ProfilePersistence.set_cookie_name(
                profile_names=[profile_name],
                cookie_names=[value])

    def _set_cookie_expiration(self, profile_name, expiration):
        value = self.client.LocalLB.ProfilePersistence.typefactory.\
                     create('LocalLB.ProfileULong')
        value.value = expiration
        value.default_flag = False
        self.client.LocalLB.ProfilePersistence.set_cookie_expiration(
                profile_names=[profile_name],
                expirations=[value])

    def delete_stickiness(self, sticky_ref):
        LOG.debug("Called delete_stickiness(), sticky: %r", sticky_ref)
        vips = db_api.virtualserver_get_all_by_sf_id(self.conf,
                                                     sticky_ref['sf_id'])
        for vip_ref in vips:
            self._remove_persistence_profile(sticky_name(sticky_ref),
                                             vip_ref)
        self.client.LocalLB.ProfilePersistence.delete_profile(
            profile_names=[sticky_name(sticky_ref)])
        LOG.debug("Ended delete_stickiness(), sticky: %r", sticky_ref)

    def _get_methods(self):
        method_enum = self.client.LocalLB.Pool.typefactory.create(
                               'LocalLB.LBMethod')
        methods = {
            'ROUND_ROBIN': method_enum.LB_METHOD_ROUND_ROBIN,
            'RATIO_MEMBER': method_enum.LB_METHOD_RATIO_MEMBER,
            'LEAST_CONNECTION_MEMBER':
                    method_enum.LB_METHOD_LEAST_CONNECTION_MEMBER,
            'PREDICTIVE_MEMBER': method_enum.LB_METHOD_PREDICTIVE_MEMBER,
            'DYNAMIC_RATIO_MEMBER': method_enum.LB_METHOD_DYNAMIC_RATIO_MEMBER,
            'LEAST_SESSIONS': method_enum.LB_METHOD_LEAST_SESSIONS,
        }
        return methods

    def _get_protocols(self):
        return ['TCP', 'HTTP']

    def get_capabilities(self):
        capabilities = {
            'algorithms': self._get_methods().keys(),
            'protocols': self._get_protocols(),
        }
        return capabilities
