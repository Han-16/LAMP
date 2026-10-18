#!/usr/bin/env python3
"""Verify repeat forwarding and validation without building or running Docker."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RepeatWrapperTests(unittest.TestCase):
    def invoke(self, script, args, defaults=None):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / '.env').write_text('')
            docker = directory / 'docker'
            docker.write_text(
                '#!/usr/bin/env python3\n'
                'import json, os, sys\n'
                'with open(os.environ["REPEAT_TEST_LOG"], "a") as f:\n'
                ' json.dump(sys.argv[1:], f); f.write("\\n")\n'
            )
            docker.chmod(0o755)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(('LAMP_', 'FREIVALDS_')) and key != 'RHO'}
            log = directory / 'docker.jsonl'
            env.update(PATH=str(directory) + os.pathsep + env['PATH'],
                       REPEAT_TEST_LOG=str(log))
            env.update(defaults or {})
            result = subprocess.run(
                ['sh', str(ROOT / 'scripts' / script), *args],
                cwd=directory, env=env, capture_output=True, text=True,
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_repeat_forwarded_to_lamp_range_commands(self):
        for script in ('run_bench.sh', 'run_gpt2_bench.sh'):
            for flags in (['--repeat', '3'], ['--repeat=3']):
                with self.subTest(script=script, flags=flags):
                    result, calls = self.invoke(script, ['all', '--range', '--from', '2', '--to', '3', *flags])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    runs = [call for call in calls if call[0] == 'run']
                    self.assertEqual(len(runs), 8 if script == 'run_bench.sh' else 4)
                    for call in runs:
                        program = next(arg for arg in call if arg.startswith('/usr/local/bin/'))
                        if Path(program).name.startswith('lamp'):
                            self.assertEqual(call[call.index('--repeat') + 1], '3')
                        else:
                            self.assertNotIn('--repeat', call)

    def test_rejects_invalid_repeat_before_docker(self):
        for script in ('run_bench.sh', 'run_gpt2_bench.sh'):
            for flags in (['--repeat'], ['--repeat', ''], ['--repeat', '0'], ['--repeat', '-1'], ['--repeat=x'], ['--repeat=']):
                with self.subTest(script=script, flags=flags):
                    result, calls = self.invoke(script, ['lamp', *flags])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('repeat', result.stderr)
                    self.assertEqual(calls, [])

    def test_forwards_environment_defaults(self):
        for script, target, key in (
            ('run_bench.sh', 'lamp', 'LAMP_REPEAT'),
            ('run_bench.sh', 'lamp_batch', 'LAMP_BATCH_REPEAT'),
            ('run_gpt2_bench.sh', 'lamp', 'LAMP_GPT2_REPEAT'),
        ):
            with self.subTest(key=key):
                result, calls = self.invoke(script, [target], {key: '2'})
                self.assertEqual(result.returncode, 0, result.stderr)
                run = next(call for call in calls if call[0] == 'run')
                self.assertIn(key + '=2', run)


if __name__ == '__main__':
    unittest.main()
