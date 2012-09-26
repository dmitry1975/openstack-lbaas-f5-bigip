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
import unittest
import mock

from f5_bigip import ltm


class TestF5BigIPLTMDriver(unittest.TestCase):
    device_ref = {'id': 'fakeid',
                  'ip': 'fakeip',
                  'port': 8443,
                  'user': 'fakeuser',
                  'password': 'fakepassword'}
    sf_ref = {'id': 'fakesfid'}
    vip_ref = {'id': 'fakevipid',
               'address': '11.0.0.1',
               'port': 80,
               'mask': '255.255.255.255',
               'extra': {'protocol': 'HTTP'}}
    server_ref = {'address': '10.0.0.2',
                  'port': 80,
                  'weight': 1}
    predictor_ref = {'type': 'ROUND_ROBIN'}
    probe_ref = {'id': 'fakeprobeid',
                 'type': 'HTTP',
                 'extra': {'send': 'fakesend',
                           'recv': 'fakerecv',
                           'interval': 5,
                           'timeout': 16}}
    sticky_ref = {'id': 'fakestickyid',
                  'sf_id': 'fakesfid',
                  'extra': {'cookie_name': 'fakecookiename',
                            'expirations': 101}}

    def setUp(self):
        self.bigip_patcher = \
                mock.patch('f5_bigip.pycontrol.BIGIP')
        self.conf = mock.Mock()
        self.BIGIP = self.bigip_patcher.start()
        self.BIGIP.return_value = self.client = mock.Mock()
        self.driver = ltm.Driver(self.conf, self.device_ref)

    def tearDown(self):
        self.bigip_patcher.stop()

    def test_init(self):
        WSDLS = ['LocalLB.Pool',
                 'LocalLB.PoolMember',
                 'LocalLB.VirtualServer',
                 'LocalLB.Monitor',
                 'LocalLB.ProfilePersistence']
        self.BIGIP.assert_called_once_with(hostname='fakeip',
                                           port=8443,
                                           username='fakeuser',
                                           password='fakepassword',
                                           fromurl=True,
                                           wsdls=WSDLS)

    def test_get_methods(self):
        method_enum = mock.Mock()
        self.client.LocalLB.Pool.typefactory.create.return_value = method_enum
        result = self.driver._get_methods()
        print(self.client.mock_calls)
        self.client.LocalLB.Pool.typefactory.create.assert_called_once_with(
                'LocalLB.LBMethod')
        expect = {
            'ROUND_ROBIN': method_enum.LB_METHOD_ROUND_ROBIN,
            'RATIO_MEMBER': method_enum.LB_METHOD_RATIO_MEMBER,
            'LEAST_CONNECTION_MEMBER':
                    method_enum.LB_METHOD_LEAST_CONNECTION_MEMBER,
            'PREDICTIVE_MEMBER': method_enum.LB_METHOD_PREDICTIVE_MEMBER,
            'DYNAMIC_RATIO_MEMBER': method_enum.LB_METHOD_DYNAMIC_RATIO_MEMBER,
            'LEAST_SESSIONS': method_enum.LB_METHOD_LEAST_SESSIONS,
        }
        self.assertEqual(result, expect)

    def test_get_protocols(self):
        result = self.driver._get_protocols()
        self.assertEqual(result, ['TCP', 'HTTP'])

    @mock.patch('f5_bigip.ltm.Driver._get_protocols', autospec=True)
    @mock.patch('f5_bigip.ltm.Driver._get_methods', autospec=True)
    def test_capabilities(self, mock_get_methods, mock_get_protocols):
        mock_get_methods_keys = mock.Mock(return_value='fakemethods')
        mock_get_methods.return_value = mock.Mock(keys=mock_get_methods_keys)
        mock_get_protocols.return_value = 'fakeprotocols'
        result = self.driver.get_capabilities()
        mock_get_methods.assert_called_once_with(self.driver)
        mock_get_protocols.assert_called_once_with(self.driver)
        self.assertEqual(result, {'algorithms': 'fakemethods',
                                  'protocols': 'fakeprotocols'})

    @mock.patch('f5_bigip.ltm.Driver._get_methods', autospec=True)
    def test_create_server_farm(self, mock_get_methods):
        self.client.LocalLB.Pool.typefactory.create.return_value = \
                'fakemembers'
        mock_get_methods.return_value = methods = mock.MagicMock()
        methods.__getitem__.return_value = "LB_METHOD_ROUND_ROBIN"
        self.driver.create_server_farm(self.sf_ref, [self.predictor_ref])
        mock_get_methods.assert_called_once_with(self.driver)
        methods.__getitem__.assert_called_once_with('ROUND_ROBIN')
        self.client.LocalLB.Pool.typefactory.create.assert_called_once_with(
            'Common.IPPortDefinitionSequence')
        self.client.LocalLB.Pool.create.assert_called_once_with(
            pool_names=['pool_fakesfid'],
            lb_methods=['LB_METHOD_ROUND_ROBIN'],
            members=['fakemembers'])

    def test_delete_server_farm(self):
        self.driver.delete_server_farm(self.sf_ref)
        self.client.LocalLB.Pool.delete_pool.assert_called_once_with(
                pool_names=['pool_fakesfid'])

    def test_define_member(self):
        self.client.LocalLB.Pool.typefactory.create.return_value = mock.Mock()
        member = self.driver._define_member(self.server_ref)
        self.client.LocalLB.Pool.typefactory.create.assert_called_once_with(
                'Common.IPPortDefinition')
        self.assertEqual(member.address, '10.0.0.2')
        self.assertEqual(member.port, 80)

    @mock.patch('f5_bigip.ltm.Driver._define_member', autospec=True)
    def test_add_real_server_to_server_farm(self, mock_define_member):
        members = mock.Mock()
        self.client.LocalLB.Pool.typefactory.create.return_value = members
        mock_define_member.return_value = 'fakemember'
        self.driver.add_real_server_to_server_farm(self.sf_ref,
                                                   self.server_ref)
        self.client.LocalLB.Pool.typefactory.create.assert_called_once_with(
            'Common.IPPortDefinitionSequence')
        self.client.LocalLB.Pool.add_member_v2.assert_called_once_with(
            pool_names=['pool_fakesfid'], members=[members])
        self.assertTrue(members.item, ['fakemember'])

    @mock.patch('f5_bigip.ltm.Driver._define_member', autospec=True)
    def test_delete_real_server_from_server_farm(self, mock_define_member):
        members = mock.Mock()
        self.client.LocalLB.Pool.typefactory.create.return_value = members
        mock_define_member.return_value = 'fakemember'
        self.driver.delete_real_server_from_server_farm(self.sf_ref,
                                                        self.server_ref)
        self.client.LocalLB.Pool.typefactory.create.assert_called_once_with(
            'Common.IPPortDefinitionSequence')
        self.client.LocalLB.Pool.remove_member.assert_called_once_with(
            pool_names=['pool_fakesfid'], members=[members])
        self.assertTrue(members.item, ['fakemember'])

    def test_define_vserver(self):
        mock_protocol = mock.Mock(PROTOCOL_TCP='PROTOCOL_TCP')
        mock_vserver = mock.Mock()
        self.client.LocalLB.VirtualServer.typefactory.create.side_effect = \
            [mock_protocol, mock_vserver]
        vserver = self.driver._define_vserver(self.vip_ref)
        self.client.LocalLB.VirtualServer.typefactory.create.assert_has_calls(
            [mock.call('Common.ProtocolType'),
             mock.call('Common.VirtualServerDefinition')])
        self.assertEqual(vserver.name, 'virtual_fakevipid')
        self.assertEqual(vserver.address, '11.0.0.1')
        self.assertEqual(vserver.port, 80)
        self.assertEqual(vserver.protocol, 'PROTOCOL_TCP')

    def test_define_vserver_resource(self):
        mock_type = mock.Mock(RESOURCE_TYPE_POOL='RESOURCE_TYPE_POOL')
        mock_resource = mock.Mock()
        self.client.LocalLB.VirtualServer.typefactory.create.side_effect = \
            [mock_type, mock_resource]
        resource = self.driver._define_vserver_resource(self.sf_ref)
        self.client.LocalLB.VirtualServer.typefactory.create.assert_has_calls(
            [mock.call('LocalLB.VirtualServer.VirtualServerType'),
             mock.call('LocalLB.VirtualServer.VirtualServerResource')])
        self.assertEqual(resource.type, 'RESOURCE_TYPE_POOL')
        self.assertEqual(resource.default_pool_name, 'pool_fakesfid')

    def test_define_tcp_profile(self):
        mock_context = mock.Mock(
            PROFILE_CONTEXT_TYPE_ALL='PROFILE_CONTEXT_TYPE_ALL')
        mock_profile = mock.Mock()
        self.client.LocalLB.VirtualServer.typefactory.create.side_effect = \
            [mock_context, mock_profile]
        profile = self.driver._define_tcp_profile()
        self.client.LocalLB.VirtualServer.typefactory.create.assert_has_calls(
            [mock.call('LocalLB.ProfileContextType'),
             mock.call('LocalLB.VirtualServer.VirtualServerProfile')])
        self.assertEqual(profile.profile_context, 'PROFILE_CONTEXT_TYPE_ALL')
        self.assertEqual(profile.profile_name, 'tcp')

    def test_define_http_profile(self):
        self.client.LocalLB.VirtualServer.typefactory.create.return_value = \
            mock.Mock()
        profile = self.driver._define_http_profile()
        self.client.LocalLB.VirtualServer.typefactory.create.\
                    assert_called_once_with('LocalLB.VirtualServer.'
                                            'VirtualServerProfile')
        self.assertEqual(profile.profile_name, 'http')

    def test_define_member_state(self):
        self.client.LocalLB.PoolMember.typefactory.create.return_value = \
            mock_member_state = mock.Mock()
        member_state = self.driver._define_member_state('fakestate',
                                                           'fakemember')
        self.assertEqual(member_state.member, 'fakemember')
        self.assertEqual(member_state.session_state, 'fakestate')

    @mock.patch('balancer.db.api.sticky_get_all_by_sf_id', autospec=True)
    @mock.patch('f5_bigip.ltm.Driver._define_vserver', autospec=True)
    @mock.patch('f5_bigip.ltm.Driver._define_vserver_resource', autospec=True)
    @mock.patch('f5_bigip.ltm.Driver._define_tcp_profile', autospec=True)
    @mock.patch('f5_bigip.ltm.Driver._define_http_profile', autospec=True)
    def test_create_virtual_ip(self,
                               mock_define_http_profile,
                               mock_define_tcp_profile,
                               mock_define_vserver_resource,
                               mock_define_vserver,
                               mock_sticky_get_all_by_sf_id):
        mock_define_vserver.return_value = 'fakevserver'
        mock_define_vserver_resource.return_value = 'fakeresource'
        mock_define_tcp_profile.return_value = 'faketcpprofile'
        mock_define_http_profile.return_value = 'fakehttpprofile'
        mock_vservers = mock.Mock()
        mock_profiles = mock.Mock()
        mock_resources = mock.Mock()
        self.client.LocalLB.VirtualServer.typefactory.create.side_effect = \
            [mock_vservers, mock_profiles, mock_resources]
        self.driver.create_virtual_ip(self.vip_ref, self.sf_ref)
        self.client.LocalLB.VirtualServer.typefactory.create.\
             assert_has_calls([mock.call('Common.VirtualServerSequence'),
                               mock.call('LocalLB.VirtualServer.'
                                         'VirtualServerProfileSequence'),
                               mock.call('LocalLB.VirtualServer.'
                                         'VirtualServerResourceSequence')])
        self.client.LocalLB.VirtualServer.create.assert_called_once_with(
            definitions=mock_vservers,
            wildmasks=['255.255.255.255'],
            resources=mock_resources,
            profiles=[mock_profiles])
        self.assertEqual(mock_vservers.item, ['fakevserver'])
        self.assertEqual(mock_profiles.item, ['faketcpprofile',
                                              'fakehttpprofile'])
        self.assertEqual(mock_resources.item, ['fakeresource'])
        self.client.LocalLB.VirtualServer.set_snat_automap.\
            assert_called_once_with(virtual_servers=['virtual_fakevipid'])

    def test_delete_virtual_ip(self):
        self.driver.delete_virtual_ip(self.vip_ref)
        self.client.LocalLB.VirtualServer.delete_virtual_server.\
            assert_called_once_with(virtual_servers=['virtual_fakevipid'])

    @mock.patch('f5_bigip.ltm.Driver._define_member_state', autospec=True)
    def test_set_member_session_state(self, mock_define_member_state):
        mock_define_member_state.return_value = 'fakememberstate'
        self.client.LocalLB.PoolMember.typefactory.create.return_value = \
            mock_states = mock.Mock()
        self.driver._set_member_session_state('fakestate',
                                              'fakemember',
                                              'fakepoolname')
        self.client.LocalLB.PoolMember.typefactory.create.\
                    assert_called_once_with('LocalLB.PoolMember.'
                                            'MemberSessionStateSequence')
        self.client.LocalLB.PoolMember.set_session_enabled_state.\
                    assert_called_once_with(pool_names=['fakepoolname'],
                                            session_states=[mock_states])

    @mock.patch('f5_bigip.ltm.Driver._set_member_session_state', autospec=True)
    @mock.patch('f5_bigip.ltm.Driver._define_member', autospec=True)
    def test_activate_real_server(self,
                                  mock_define_member,
                                  mock_set_member_state):
        mock_define_member.return_value = 'fakemember'
        self.client.LocalLB.Pool.typefactory.create.return_value = \
            mock_state = mock.Mock(STATE_ENABLED='STATE_ENABLED')
        self.driver.activate_real_server(self.sf_ref, self.server_ref)
        self.client.LocalLB.Pool.typefactory.create.\
                    assert_called_once_with('Common.EnabledState')
        mock_define_member.assert_called_once_with(self.driver,
                                                      self.server_ref)
        mock_set_member_state.assert_called_once_with(self.driver,
                                                      'STATE_ENABLED',
                                                      'fakemember',
                                                      'pool_fakesfid')

    @mock.patch('f5_bigip.ltm.Driver._set_member_session_state', autospec=True)
    @mock.patch('f5_bigip.ltm.Driver._define_member', autospec=True)
    def test_suspend_real_server(self,
                                 mock_define_member,
                                 mock_set_member_state):
        mock_define_member.return_value = 'fakemember'
        self.client.LocalLB.Pool.typefactory.create.return_value = \
            mock_state = mock.Mock(STATE_DISABLED='STATE_DISABLED')
        self.driver.suspend_real_server(self.sf_ref, self.server_ref)
        self.client.LocalLB.Pool.typefactory.create.\
                    assert_called_once_with('Common.EnabledState')
        mock_define_member.assert_called_once_with(self.driver,
                                                   self.server_ref)
        mock_set_member_state.assert_called_once_with(self.driver,
                                                      'STATE_DISABLED',
                                                      'fakemember',
                                                      'pool_fakesfid')

    def test_add_probe_to_server_farm(self):
        mock_assoc = mock.Mock()
        mock_assoc.monitor_rule.monitor_templates = []
        mock_assoc.monitor_rule.type = 'MONITOR_RULE_TYPE_NONE'
        self.client.LocalLB.Pool.get_monitor_association.return_value = \
            [mock_assoc]
        mock_type = mock.Mock(
            MONITOR_RULE_TYPE_NONE='MONITOR_RULE_TYPE_NONE',
            MONITOR_RULE_TYPE_SINGLE='MONITOR_RULE_TYPE_SINGLE',
            MONITOR_RULE_TYPE_AND_LIST='MONITOR_RULE_TYPE_AND_LIST'
        )
        self.client.LocalLB.Pool.typefactory.create.return_value = mock_type
        # Set instead none
        self.driver.add_probe_to_server_farm(self.sf_ref, self.probe_ref)
        self.client.LocalLB.Pool.get_monitor_association.\
                    assert_called_once_with(pool_names=['pool_fakesfid'])
        self.client.LocalLB.Pool.typefactory.create.\
                    assert_called_once_with('LocalLB.MonitorRuleType')
        self.client.LocalLB.Pool.set_monitor_association.\
                    assert_called_once_with(monitor_associations=[mock_assoc])
        self.assertEqual(mock_assoc.monitor_rule.monitor_templates,
                         ['monitor_fakeprobeid'])
        self.assertEqual(mock_assoc.monitor_rule.type,
                         'MONITOR_RULE_TYPE_SINGLE')
        # Add fakeprodeid0
        self.driver.add_probe_to_server_farm(self.sf_ref,
                                             {'id': 'fakeprobeid0'})
        self.assertEqual(mock_assoc.monitor_rule.type,
                         'MONITOR_RULE_TYPE_AND_LIST')
        # Add fakeprobeid1
        self.driver.add_probe_to_server_farm(self.sf_ref,
                                             {'id': 'fakeprobeid1'})
        self.assertEqual(mock_assoc.monitor_rule.type,
                         'MONITOR_RULE_TYPE_AND_LIST')
        self.assertEqual(mock_assoc.monitor_rule.monitor_templates, [
                             'monitor_fakeprobeid',
                             'monitor_fakeprobeid0',
                             'monitor_fakeprobeid1'
                         ])

    def test_add_probe_to_server_farm_none(self):
        mock_assoc = mock.Mock()
        mock_assoc.monitor_rule.monitor_templates = ['/Common/none']
        mock_assoc.monitor_rule.type = 'MONITOR_RULE_TYPE_SINGLE'
        self.client.LocalLB.Pool.get_monitor_association.return_value = \
            [mock_assoc]
        mock_type = mock.Mock(
            MONITOR_RULE_TYPE_NONE='MONITOR_RULE_TYPE_NONE',
            MONITOR_RULE_TYPE_SINGLE='MONITOR_RULE_TYPE_SINGLE',
            MONITOR_RULE_TYPE_AND_LIST='MONITOR_RULE_TYPE_AND_LIST'
        )
        self.client.LocalLB.Pool.typefactory.create.return_value = mock_type
        self.driver.add_probe_to_server_farm(self.sf_ref, self.probe_ref)
        self.assertEqual(mock_assoc.monitor_rule.type,
                         'MONITOR_RULE_TYPE_SINGLE')
        self.assertEqual(mock_assoc.monitor_rule.monitor_templates,
                         ['monitor_fakeprobeid'])

    def test_delete_probe_from_server_farm(self):
        mock_assoc = mock.Mock()
        mock_assoc.monitor_rule.type = 'MONITOR_RULE_TYPE_SINGLE'
        mock_type = mock.Mock(
            MONITOR_RULE_TYPE_NONE='MONITOR_RULE_TYPE_NONE',
            MONITOR_RULE_TYPE_SINGLE='MONITOR_RULE_TYPE_SINGLE',
            MONITOR_RULE_TYPE_AND_LIST='MONITOR_RULE_TYPE_AND_LIST'
        )
        self.client.LocalLB.Pool.typefactory.create.return_value = mock_type
        mock_assoc.monitor_rule.monitor_templates = [
            '/Common/monitor_fake1',
            '/Common/monitor_fakeprobeid',
            '/Common/monitor_fake2',
        ]
        self.client.LocalLB.Pool.get_monitor_association.return_value = \
            [mock_assoc]
        # Remove 'monitor_fakeprobeid'
        self.driver.delete_probe_from_server_farm(self.sf_ref, self.probe_ref)
        self.client.LocalLB.Pool.get_monitor_association.\
                    assert_called_once_with(pool_names=['pool_fakesfid'])
        self.client.LocalLB.Pool.typefactory.create.\
                    assert_called_once_with('LocalLB.MonitorRuleType')
        self.client.LocalLB.Pool.set_monitor_association.\
                    assert_called_once_with(monitor_associations=[mock_assoc])
        self.assertEqual(mock_assoc.monitor_rule.monitor_templates,
                         ['/Common/monitor_fake1', '/Common/monitor_fake2'])
        self.assertEqual(mock_assoc.monitor_rule.type,
                         'MONITOR_RULE_TYPE_AND_LIST')
        # Remove 'fake1'
        self.driver.delete_probe_from_server_farm(self.sf_ref,
                                                  {'id': 'fake1'})
        self.assertEqual(mock_assoc.monitor_rule.type,
                         'MONITOR_RULE_TYPE_SINGLE')
        # Remove 'fake2'
        self.driver.delete_probe_from_server_farm(self.sf_ref,
                                                  {'id': 'fake2'})
        self.assertEqual(mock_assoc.monitor_rule.type,
                         'MONITOR_RULE_TYPE_NONE')

    def test_delete_probe(self):
        self.driver.delete_probe(self.probe_ref)
        self.client.LocalLB.Monitor.delete_template.\
            assert_called_once_with(template_names=['monitor_fakeprobeid'])

    def test_define_str_value(self):
        self.client.LocalLB.Monitor.typefactory.create.return_value = \
            mock.Mock()
        value = self.driver._define_str_value('fakevalue', 'faketype')
        self.client.LocalLB.Monitor.typefactory.create.\
                    assert_called_once_with('LocalLB.Monitor.StringValue')
        self.assertEqual(value.type.value, 'faketype')
        self.assertEqual(value.value, 'fakevalue')

    @mock.patch('f5_bigip.ltm.Driver._define_str_value', autospec=True)
    def test_create_http_monitor_template(self, mock_define_str_value):
        mock_template = mock.Mock()
        mock_define_str_value.side_effect = iter(['fakevalue0', 'fakevalue1'])
        mock_type = mock.Mock(
                ATYPE_STAR_ADDRESS_STAR_PORT='ATYPE_STAR_ADDRESS_STAR_PORT')
        mock_attrs = mock.Mock()
        mock_value_type = mock.Mock(STYPE_SEND='STYPE_SEND',
                                    STYPE_RECEIVE='STYPE_RECEIVE')
        self.client.LocalLB.Monitor.typefactory.create.side_effect = \
            [mock_type, mock_attrs, mock_value_type]
        self.driver._create_http_monitor_template('template',
                                                  self.probe_ref)
        self.client.LocalLB.Monitor.typefactory.create.assert_has_calls(
            [mock.call('LocalLB.AddressType'),
             mock.call('LocalLB.Monitor.CommonAttributes'),
             mock.call('LocalLB.Monitor.StrPropertyType')])
        mock_define_str_value.assert_has_calls(
            [mock.call(self.driver, 'fakesend', 'STYPE_SEND'),
             mock.call(self.driver, 'fakerecv', 'STYPE_RECEIVE')])
        self.client.LocalLB.Monitor.create_template.\
                    assert_called_once_with(templates=['template'],
                                            template_attributes=[mock_attrs])
        self.client.LocalLB.Monitor.set_template_string_property.\
             assert_called_once_with(template_names=[
                                         'monitor_fakeprobeid',
                                         'monitor_fakeprobeid',
                                     ],
                                     values=['fakevalue0', 'fakevalue1'])
        self.assertEqual(mock_attrs.parent_template, 'http')
        self.assertEqual(mock_attrs.is_read_only, False)
        self.assertEqual(mock_attrs.is_directly_usable, True)
        self.assertEqual(mock_attrs.interval, 5)
        self.assertEqual(mock_attrs.timeout, 16)
        self.assertEqual(mock_attrs.dest_ipport.address_type,
                         'ATYPE_STAR_ADDRESS_STAR_PORT')
        self.assertEqual(mock_attrs.dest_ipport.ipport.address, '0.0.0.0')
        self.assertEqual(mock_attrs.dest_ipport.ipport.port, 0)

    @mock.patch('f5_bigip.ltm.Driver._create_http_monitor_template',
                autospec=True)
    def test_create_probe(self, mock_create_http_monitor_template):
        mock_type = mock.Mock(TTYPE_HTTP='TTYPE_HTTP')
        mock_template = mock.Mock()
        self.client.LocalLB.Monitor.typefactory.create.side_effect = \
            [mock_template, mock_type]
        self.driver.create_probe(self.probe_ref)
        mock_create_http_monitor_template.\
            assert_called_once_with(self.driver, mock_template, self.probe_ref)
        self.assertEqual(mock_template.template_type, 'TTYPE_HTTP')

    def test_set_cookie_name(self):
        self.client.LocalLB.ProfilePersistence.typefactory.create.\
             return_value = mock_value = mock.Mock()
        self.driver._set_cookie_name('profile0', 'cookiename0')
        self.client.LocalLB.ProfilePersistence.typefactory.create.\
             assert_called_once_with('LocalLB.ProfileString')
        self.client.LocalLB.ProfilePersistence.set_cookie_name.\
             assert_called_once_with(profile_names=['profile0'],
                                     cookie_names=[mock_value])
        self.assertEqual(mock_value.value, 'cookiename0')
        self.assertEqual(mock_value.default_flag, False)

    def test_set_cookie_expiration(self):
        self.client.LocalLB.ProfilePersistence.typefactory.create.\
            return_value = mock_value = mock.Mock()
        self.driver._set_cookie_expiration('profile0', 101)
        self.client.LocalLB.ProfilePersistence.typefactory.create.\
            assert_called_once_with('LocalLB.ProfileULong')
        self.client.LocalLB.ProfilePersistence.set_cookie_expiration.\
            assert_called_once_with(profile_names=['profile0'],
                                    expirations=[mock_value])
        self.assertEqual(mock_value.value, 101)
        self.assertEqual(mock_value.default_flag, False)

    def test_create_cookie_insert(self):
        mock_modes = mock.Mock(
            PERSISTENCE_MODE_COOKIE='PERSISTENCE_MODE_COOKIE')
        self.client.LocalLB.ProfilePersistence.typefactory.create.\
            return_value = mock_modes
        self.driver._create_cookie_insert(self.sticky_ref)
        self.client.LocalLB.ProfilePersistence.typefactory.create.\
            assert_called_once_with('LocalLB.PersistenceMode')
        self.client.LocalLB.ProfilePersistence.create.\
            assert_called_once_with(profile_names=['sticky_fakestickyid'],
                                    modes=['PERSISTENCE_MODE_COOKIE'])

    def test_define_persistence(self):
        self.client.LocalLB.VirtualServer.typefactory.create.return_value = \
            mock_profile = mock.Mock()
        self.driver._define_persistence('profile0')
        self.client.LocalLB.VirtualServer.typefactory.create.\
             assert_called_once_with('LocalLB.VirtualServer.'
                                     'VirtualServerPersistence')
        self.assertEqual(mock_profile.profile_name, 'profile0')
        self.assertEqual(mock_profile.default_profile, False)

    @mock.patch('f5_bigip.ltm.Driver._define_persistence', autospec=True)
    def test_add_persistence_profile(self, mock_define_persistence):
        mock_define_persistence.return_value = 'persistence0'
        self.client.LocalLB.VirtualServer.typefactory.create.return_value = \
            mock_profiles = mock.Mock()
        self.driver._add_persistence_profile('profile0', self.vip_ref)
        mock_define_persistence.assert_called_once_with(self.driver,
                                                        'profile0',
                                                        default=True)
        self.client.LocalLB.VirtualServer.add_persistence_profile.\
            assert_called_once_with(virtual_servers=['virtual_fakevipid'],
                                    profiles=[mock_profiles])
        self.assertEqual(mock_profiles.item, ['persistence0'])

    @mock.patch('f5_bigip.ltm.Driver._define_persistence', autospec=True)
    def test_remove_persistence_profile(self, mock_define_persistence):
        mock_define_persistence.return_value = 'persistence0'
        self.client.LocalLB.VirtualServer.typefactory.create.return_value = \
            mock_profiles = mock.Mock()
        self.driver._remove_persistence_profile('profile0', self.vip_ref)
        self.client.LocalLB.VirtualServer.remove_persistence_profile.\
            assert_called_once_with(virtual_servers=['virtual_fakevipid'],
                                    profiles=[mock_profiles])
        self.assertEqual(mock_profiles.item, ['persistence0'])

    @mock.patch('f5_bigip.ltm.Driver._remove_persistence_profile',
                autospec=True)
    @mock.patch('balancer.db.api.virtualserver_get_all_by_sf_id',
                autospec=True)
    def test_delete_stickiness(self, mock_virtualserver_get_all_by_sf_id,
                               mock_remove_persistence_profile):
        mock_virtualserver_get_all_by_sf_id.return_value = ['fakevip0',
                                                            'fakevip1']
        self.driver.delete_stickiness(self.sticky_ref)
        mock_virtualserver_get_all_by_sf_id.assert_called_once_with(self.conf,
            'fakesfid')
        mock_remove_persistence_profile.assert_has_calls([
            mock.call(self.driver, 'sticky_fakestickyid', 'fakevip0'),
            mock.call(self.driver, 'sticky_fakestickyid', 'fakevip1')])
        self.client.LocalLB.ProfilePersistence.delete_profile.\
            assert_called_once_with(profile_names=['sticky_fakestickyid'])
