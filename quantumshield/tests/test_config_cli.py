
import unittest
import sys
import os
from click.testing import CliRunner
from unittest.mock import MagicMock, patch

# Adjust path to AITF_AI root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from quantumshield.config.settings import Settings, get_settings
from quantumshield.cli.main import cli

class TestConfigCLI(unittest.TestCase):
    def test_settings_defaults(self):
        settings = Settings()
        self.assertIn("sqlite", settings.database_url)
    
    def test_get_settings_cache(self):
        s1 = get_settings()
        s2 = get_settings()
        self.assertIs(s1, s2)

    @patch('quantumshield.cli.main.QuantumShieldEngine')
    def test_cli_start(self, mock_engine_cls):
        # Mock the engine instance and its start method
        mock_engine = mock_engine_cls.return_value
        mock_engine.start = MagicMock(side_effect=None)  # Just return None (coroutine handled mock?)
        
        # Note: cli.start runs asyncio.run, so we need to mock that or ensure the mock returns awaitable
        # Since asyncio.run executes the coroutine, we can just let it run if we mock the inner async start
        # OR we mock asyncio.run
        
        runner = CliRunner()
        # Mock asyncio.run to avoid actual loop execution if complex
        with patch('asyncio.run') as mock_run:
            result = runner.invoke(cli, ['start'])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Starting QuantumShield", result.output)
            mock_run.assert_called()

    def test_cli_status(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['status'])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Running", result.output)

if __name__ == "__main__":
    unittest.main()
