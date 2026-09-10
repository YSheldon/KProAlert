import unittest
from install_metrics import make_event, validate_event, summarize, new_installation_id


INSTALL='a'*32


class InstallMetricsTests(unittest.TestCase):
    def event(self, kind='install_success', day=100, event_id='b'*32):
        return make_event(consent=True, installation_id=INSTALL, event_id=event_id,
                          day=day, kind=kind, version='1.2.0.267', architecture='x64',
                          os_family='windows11', state='unknown')

    def test_disabled_creates_no_event(self):
        self.assertIsNone(make_event(consent=False))
        with self.assertRaises(ValueError):
            make_event(consent='yes')

    def test_identifier_requires_consent_and_is_random(self):
        self.assertIsNone(new_installation_id())
        first=new_installation_id(consent=True)
        self.assertRegex(first,'^[a-f0-9]{32}$')
        self.assertNotEqual(first,new_installation_id(consent=True))

    def test_minimal_fields_only(self):
        event=self.event()
        self.assertEqual(set(event),{'schema','installationId','eventId','day','kind',
                                   'version','architecture','osFamily','state','simulated'})
        self.assertNotIn('deviceId',event)
        event['hostname']='private'
        with self.assertRaises(ValueError):
            validate_event(event)

    def test_no_free_text(self):
        for key,value in [('version','private path'),('state','username'),('day',True),
                          ('installationId','MachineGuid'),('kind','ransomware')]:
            event=self.event()
            event[key]=value
            with self.assertRaises(ValueError):
                validate_event(event)

    def test_download_does_not_count_as_install(self):
        result=summarize([self.event('install_started')],today=100)
        self.assertEqual(result['successfulInstallations'],0)
        self.assertIsNone(result['uniqueUsers'])

    def test_simulations_are_excluded(self):
        event=self.event()
        event['simulated']=True
        self.assertEqual(summarize([event],today=100)['successfulInstallations'],0)

    def test_duplicate_event_does_not_double_count(self):
        event=self.event()
        result=summarize([event,event],today=100)
        self.assertEqual(result['successfulInstallations'],1)

    def test_conflicting_duplicate_is_rejected(self):
        event=self.event()
        changed={**event,'kind':'install_failure'}
        with self.assertRaises(ValueError):
            summarize([event,changed],today=100)

    def test_active_requires_recent_observation_and_success(self):
        success=self.event(day=60)
        active=self.event('status',day=98,event_id='c'*32)
        result=summarize([success,active],today=100)
        self.assertEqual(result['activeInstallations7d'],1)
        self.assertEqual(result['activeInstallations30d'],1)
        self.assertEqual(summarize([active],today=100)['activeInstallations7d'],0)
        self.assertEqual(result['protectionVerified'],False)

    def test_future_clock_does_not_inflate_activity(self):
        with self.assertRaises(ValueError):
            summarize([self.event(day=101)],today=100)

    def test_uninstall_not_reported_active(self):
        records=[self.event(),self.event('uninstall',day=101,event_id='d'*32)]
        self.assertEqual(summarize(records,today=101)['activeInstallations7d'],0)
        records.append(self.event('status',day=102,event_id='e'*32))
        self.assertEqual(summarize(records,today=102)['activeInstallations7d'],0)


if __name__=='__main__':
    unittest.main()
