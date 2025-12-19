
import unittest
import sys
import os
from fastapi.testclient import TestClient

# Adjust path to AITF_AI root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from quantumshield.api.rest_api import app

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

if __name__ == "__main__":
    unittest.main()
