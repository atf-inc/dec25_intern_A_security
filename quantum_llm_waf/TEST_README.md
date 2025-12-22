# Test Suite for quantum_llm_waf

This comprehensive test suite validates all features of the quantum_llm_waf project, including PurpleLlama components and secure_agent.

## Prerequisites

1. **Python 3.8+** installed
2. **Dependencies installed**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Variables**:
   - `OPENAI_API_KEY` (required for ChatGPT API tests and secure_agent)
   - `HF_TOKEN` (optional, for Prompt-Guard-86M model download)
   - `OPENAI_MODEL` (optional, defaults to `gpt-4o-mini`)

4. **Create `.env` file** (optional, in project root):
   ```env
   OPENAI_API_KEY=your-openai-key-here
   OPENAI_MODEL=gpt-4o-mini
   HF_TOKEN=your-huggingface-token-here
   ```

## Running the Tests

From the `quantum_llm_waf` directory:

```bash
python test.py
```

Or on Windows:
```powershell
python test.py
```

## What Gets Tested

### 1. Environment Check
- Verifies `OPENAI_API_KEY` is set
- Checks for `HF_TOKEN` (optional)

### 2. Prompt-Guard-86M Scanner (Local Model)
- Tests firewall initialization with Prompt-Guard scanner
- Tests unsafe input detection (jailbreak attempts, prompt injections)
- Tests safe input detection (normal queries)
- Uses the locally downloaded `meta-llama/Prompt-Guard-86M` model

### 3. CodeShield Scanner
- Tests code security scanning
- Detects insecure code patterns (MD5 hashing, command injection, etc.)
- Validates safe code passes through

### 4. ChatGPT Guard (secure_agent)
- Tests ChatGPT-based safety guard initialization
- Tests unsafe input blocking
- Tests safe input processing
- Tests output guard functionality

### 5. Secure Agent Integration
- Tests full secure_agent workflow
- Tests safe input processing
- Tests unsafe input blocking at agent level

### 6. LlamaFirewall Integration
- Tests multi-scanner configuration
- Tests user input scanning
- Tests assistant output scanning

### 7. Regex Scanner
- Tests pattern detection (credit cards, emails, phone numbers)
- Tests PII detection capabilities

### 8. Hidden ASCII Scanner
- Tests detection of hidden/zero-width characters
- Tests obfuscation detection

### 9. Model Download Check
- Verifies Prompt-Guard-86M model access
- Checks if model is already downloaded or can be downloaded

## Expected Output

The test suite provides:
- ✅ Green checkmarks for passed tests
- ❌ Red X marks for failed tests
- Detailed messages for each test
- Summary statistics at the end
- Category-wise breakdown of results

## Troubleshooting

### Model Download Issues
If Prompt-Guard-86M fails to download:
1. Ensure you have a HuggingFace account
2. Set `HF_TOKEN` environment variable
3. Run: `huggingface-cli login`

### OpenAI API Issues
If ChatGPT tests fail:
1. Verify `OPENAI_API_KEY` is set correctly
2. Check API key has sufficient credits
3. Ensure model name (`gpt-4o-mini`) is accessible

### Import Errors
If you see import errors:
1. Ensure virtual environment is activated
2. Run `pip install -r requirements.txt`
3. Check Python version (3.8+ required)

## Exit Codes

- `0`: All tests passed
- `1`: One or more tests failed



