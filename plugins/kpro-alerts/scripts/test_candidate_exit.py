import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from candidate_validation import VERIFIER


@unittest.skipUnless(os.name == 'nt', 'Windows PowerShell nested script exit contract')
class CandidateExitTests(unittest.TestCase):
    def test_nested_exit_reaches_process_boundary(self):
        with tempfile.TemporaryDirectory(prefix='FalconPro-exit-') as temporary:
            root = Path(temporary)
            inner = root / 'inner.ps1'
            wrapper = root / 'Invoke-FalconProCandidateValidation.ps1'
            wrapper.write_text("& (Join-Path $PSScriptRoot 'inner.ps1')\n", encoding='utf-8')
            tail = VERIFIER[VERIFIER.index('    # All candidate PS1 signatures'):]
            code = ("$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;"
                    "$held=@();$invoke=@{};$nativeExitCode=0;$a=@{SourceRoot='" +
                    str(root).replace("'", "''") + "'};try{\n" + tail)
            cases = [("'native-reply';exit " + str(result), result) for result in (0, 1, 23)]
            cases += [("throw 'fixture-error'", 1), ("Write-Error 'fixture-error'", 1)]
            for body, result in cases:
                inner.write_text(body + '\n', encoding='utf-8')
                reply = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive',
                                        '-ExecutionPolicy', 'RemoteSigned', '-Command', code],
                                       capture_output=True, text=True, timeout=15)
                self.assertEqual(reply.returncode, result, reply.stdout + reply.stderr)


if __name__ == '__main__':
    unittest.main()
