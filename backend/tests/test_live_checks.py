"""Tests for v4.2 live DNS and redirect integration; run with python -m unittest discover -s tests -v."""
import unittest
from pathlib import Path
from unittest.mock import patch
from app.threat_engine import assess_live_url
from app.media_tools import qr_report

class ThreatTests(unittest.TestCase):
    @patch('app.threat_engine.redirect_chain', return_value={'status':'completed','chain':[{'url':'https://example.com','status_code':200}],'final_url':'https://example.com'})
    @patch('app.threat_engine.dns_lookup', return_value={'status':'completed','addresses':['93.184.215.14']})
    def test_successful_network_checks(self,*_):
        report=assess_live_url('https://example.com')
        self.assertEqual(report['checks_completed'],2)
        self.assertEqual(report['checks_available'],2)
        self.assertEqual(set(report['live_checks']), {'dns','redirects'})
        self.assertEqual(report['verification_status'],'completed')
        self.assertEqual(report['score'],0)

    @patch('app.threat_engine.redirect_chain', return_value={'status':'unavailable','detail':'TLS problem'})
    @patch('app.threat_engine.dns_lookup', return_value={'status':'completed','addresses':['93.184.215.14']})
    def test_partial(self,*_):
        report=assess_live_url('https://example.com')
        self.assertEqual(report['checks_completed'],1)
        self.assertEqual(report['verification_status'],'partial')
        self.assertIn('Some live network checks',report['coverage_message'])

    @patch('app.threat_engine.redirect_chain')
    @patch('app.threat_engine.dns_lookup', return_value={'status':'error','detail':'private destination'})
    def test_private_ip_not_probed(self,_,redirects):
        report=assess_live_url('http://127.0.0.1/')
        self.assertEqual(report['live_checks']['redirects']['status'],'not_performed')
        redirects.assert_not_called()

    @patch('app.threat_engine.redirect_chain', return_value={'status':'completed','chain':[], 'final_url':'http://paypal-account-verify.example.com/login'})
    @patch('app.threat_engine.dns_lookup', return_value={'status':'completed','addresses':['93.184.215.14']})
    def test_redirect_destination_structural_score(self,*_):
        report=assess_live_url('https://example.com')
        self.assertGreaterEqual(report['score'],20)
        self.assertEqual(report['final_url'],'http://paypal-account-verify.example.com/login')
        self.assertEqual(report['live_checks']['redirects']['final_url'],report['final_url'])

    def test_qr_decoder(self):
        sample=Path(__file__).parent/'qr_sample.png'
        report=qr_report(sample.read_bytes(),analyzer=lambda url:{'url':url,'score':0,'level':'Low','live_checks':{'dns':{},'redirects':{}},'reasons':[]})
        self.assertEqual(report['count'],1)
        self.assertEqual(report['items'][0]['kind'],'URL')

if __name__=='__main__': unittest.main()
