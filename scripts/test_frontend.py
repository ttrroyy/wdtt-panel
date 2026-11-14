import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('frontend',Path(__file__).with_name('frontend.py'))
frontend=importlib.util.module_from_spec(spec);spec.loader.exec_module(frontend)

class FrontendTests(unittest.TestCase):
    def test_both_proxies_share_one_loopback_upstream_and_certbot_webroot(self):
        settings=dict(domain='panel.example.org',upstream='127.0.0.1:2860')
        for render in (frontend.nginx_config,frontend.caddy_config):
            secure=render(settings,True);bootstrap=render(settings,False)
            self.assertIn('127.0.0.1:2860',secure)
            self.assertIn('/.well-known/acme-challenge/',secure)
            self.assertIn(str(frontend.TLS)+'/privkey.pem',secure)
            self.assertNotIn('127.0.0.1:2860',bootstrap)
            self.assertNotIn('/wdtt/',secure)
            self.assertNotIn('2096',secure)
        for value in ('example.org; shutdown','https://example.org','example.org/path','x\nreturn 200;'):
            with self.assertRaises(ValueError):frontend.domain(value)

    def test_proxy_validation_failure_restores_previous_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'panel.conf';path.write_text('existing vhost')
            with patch.object(frontend,'NGINX',path),patch.object(frontend,'proxy_reload',side_effect=RuntimeError('bad config')):
                with self.assertRaises(RuntimeError):frontend.write_proxy(dict(mode='nginx',domain='panel.example.org',upstream='127.0.0.1:2860'),True)
            self.assertEqual(path.read_text(),'existing vhost')

    def test_renewal_of_another_certificate_does_not_touch_proxy(self):
        with patch.object(frontend,'read_state',return_value=dict(mode='caddy',cert_name='wdtt-panel-panel.example.org')),patch.object(frontend,'install_cert') as install,patch.object(frontend,'proxy_reload') as reload,patch.dict(frontend.os.environ,{'RENEWED_LINEAGE':'/etc/letsencrypt/live/someone-else'}):
            frontend.renew();install.assert_not_called();reload.assert_not_called()

if __name__=='__main__':unittest.main()

class ShareQrTests(unittest.TestCase):
    def test_qr_canvas_is_square_before_it_is_drawn(self):
        # The popover places itself on open: an empty canvas lower than the QR left it cut off at the bottom of the page.
        html=(Path(__file__).parents[1]/'panel/web/html/modals/wdtt_user_modal.html').read_text(encoding='utf-8')
        self.assertIn(':id="\'user-share-qr-\'+entry.id" width="384" height="384"',html)
        self.assertIn('size:384',html)
