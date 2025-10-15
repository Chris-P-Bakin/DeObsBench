# DeObsBench: Deobfuscation Benchmark for Large Language Models

A comprehensive benchmark for evaluating Large Language Models (LLMs) on their ability to deobfuscate malware and extract Indicators of Compromise (IOCs) from PowerShell samples.

## Overview

DeObsBench is a research tool designed to systematically evaluate how well different LLMs can:
- Deobfuscate obfuscated PowerShell malware samples
- Extract Indicators of Compromise (IOCs) from malware code
- Compare performance across multiple models using standardized metrics

The benchmark uses real-world malware samples and provides detailed performance analytics, making it valuable for cybersecurity research and LLM evaluation.

## Features

- **Multi-Model Testing**: Support for testing multiple LLM models via OpenRouter API
- **Comprehensive IOC Extraction**: Extracts various types of IOCs including URLs, IPs, domains, file names, and more
- **Performance Analytics**: Detailed metrics and visualizations for model comparison
- **Ground Truth Comparison**: Compares extracted IOCs against known ground truth data
- **Configurable Testing**: Flexible configuration for different testing scenarios

## Project Structure

```
DeObsBench/
├── README.md                 # This file
├── LICENSE                   # GPL v3 License
├── requirements.txt          # Python dependencies
├── config.yaml              # Main configuration file
├── prompts.yaml             # LLM prompt templates
├── models.txt               # List of models to test
├── env.template            # Environment variables template
├── ioc_extraction_test.py  # Main testing script
├── generate_graphs.py      # Graph generation for research
├── samples/                # Malware sample directory
├── graphs/                 # Generated visualizations
├── reports/                # Test results and reports
└── deobsbench.db          # SQLite database for results
```

## Installation

### Prerequisites

- Python 3.8 or higher
- OpenRouter API key (get one at [openrouter.ai](https://openrouter.ai/keys))

### Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd DeObsBench
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**:
   ```bash
   cp env.template .env
   # Edit .env and add your OpenRouter API key
   ```

4. **Prepare samples** (if not already present):
   - Place malware samples in the `samples/` directory
   - Ensure samples are named with their SHA256 hash (e.g., `abc123...def.sample`)
   - Create a `samples/sample_index.json` file with sample metadata

   **Example `samples/sample_index.json` structure:**
   ```json
   {
     "samples": [
       {
         "name": "0a0b5f95f37a91f99e849ab14a53c740198abca9b4fe3322e6ff9f34b810dfe7.sample",
         "path": "samples/0a0b5f95f37a91f99e849ab14a53c740198abca9b4fe3322e6ff9f34b810dfe7.sample",
         "obfuscation_methods": [
           "base64"
         ],
         "layers": 1,
         "indicators": [
           {
             "indicator": "hxxp://labid[.]com[.]my/spe/spendy.exe",
             "obfuscated": "True"
           },
           {
             "indicator": "spendy.exe",
             "obfuscated": "True"
           },
           {
             "indicator": "labid[.]com[.]my",
             "obfuscated": "True"
           }
         ]
       },
       {
         "name": "1b1ba49163765e2072e15f5b02598e88209e91c89f58d71ca99e2e2ee241dc44.sample",
         "path": "samples/1b1ba49163765e2072e15f5b02598e88209e91c89f58d71ca99e2e2ee241dc44.sample",
         "obfuscation_methods": [
           "base64",
           "concatenation",
           "object_renaming"
         ],
         "layers": 2,
         "indicators": [
           {
             "indicator": "hxxps://dfiwod[.]com/2.php",
             "obfuscated": "True"
           },
           {
             "indicator": "dfiwod[.]com",
             "obfuscated": "True"
           },
           {
             "indicator": "python.exe",
             "obfuscated": "False"
           }
         ],
         "comments": "Sample has a large number of indicators"
       }
     ]
   }
   ```

   **Sample Index Fields:**
   - `name`: Sample filename (SHA256 hash + .sample extension)
   - `path`: Relative path to the sample file
   - `obfuscation_methods`: Array of obfuscation techniques used (base64, concatenation, object_renaming, etc.)
   - `layers`: Number of obfuscation layers (0 = no obfuscation, 1+ = obfuscated)
   - `indicators`: Array of ground truth IOCs with obfuscation status
   - `comments`: Optional notes about the sample

## Configuration

### Main Configuration (`config.yaml`)

The main configuration file controls:
- **OpenRouter settings**: API parameters, timeouts, retry logic
- **Processing settings**: File size limits, rate limiting
- **IOC categories**: Which types of IOCs to extract
- **Output settings**: Result file locations and backup options

### Prompt Templates (`prompts.yaml`)

Customize the prompts used for IOC extraction. The default prompt is designed for PowerShell malware analysis.

### Models (`models.txt`)

List the LLM models to test, one per line. Supported models include:
- `anthropic/claude-sonnet-4`
- `google/gemini-2.5-flash`
- `deepseek/deepseek-chat-v3-0324`
- And many more via OpenRouter

## Usage

### Basic Testing

Run IOC extraction tests on all configured models:

```bash
python ioc_extraction_test.py --models models.txt
```

### Advanced Options

```bash
python ioc_extraction_test.py \
    --models models.txt \
    --config config.yaml \
    --prompts prompts.yaml \
    --samples samples/ \
    --output results.json \
    --verbose
```

### Generate Graphs

After running tests, generate publication-quality visualizations:

```bash
python generate_graphs.py --run-id <run_id> --output-dir graphs/
```

## Configuration Options

### IOC Categories

Configure which types of IOCs to extract in `config.yaml`:

```yaml
ioc_categories:
  url:
    enabled: true
    examples: ["https://badstuff.com", "http://stats.malware.net"]
  ip:
    enabled: true
    examples: ["192.168.1.100", "10.0.0.1"]
  domain:
    enabled: true
    examples: ["badstuff.com", "stats.malware.net"]
  file_name:
    enabled: true
    examples: ["malicious.exe", "trojan.dll"]
  # ... more categories
```

### API Settings

Configure OpenRouter API behavior:

```yaml
openrouter:
  temperature: 0.1          # Low temperature for consistent results
  max_tokens: 2000          # Maximum response length
  timeout: 60               # API timeout in seconds
  use_structured_output: true  # Use structured JSON output
  fallback_to_text: true   # Fallback to text parsing if needed
```

## Output and Results

### Database Storage

Results are stored in SQLite database (`deobsbench.db`) with the following structure:
- **Test runs**: Metadata about each test execution
- **Model results**: Performance metrics per model
- **Sample results**: Detailed results per sample
- **IOC extractions**: Individual IOC findings

### Generated Reports

The benchmark generates:
- **JSON results**: Detailed extraction results
- **Performance graphs**: Model comparison visualizations
- **Accuracy metrics**: Precision, recall, F1 scores
- **Timing analysis**: Processing time comparisons

## API Integration

### OpenRouter Configuration

DeObsBench uses OpenRouter for LLM API access, supporting:
- Multiple model providers (Anthropic, Google, DeepSeek, etc.)
- Structured output for consistent JSON responses
- Rate limiting and retry logic
- Cost tracking and usage monitoring

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Citation

If you use DeObsBench in your research, please cite:

```bibtex
@software{deobsbench,
  title={DeObsBench: Deobfuscation Benchmark for Large Language Models},
  author={[Your Name]},
  year={2024},
  url={https://github.com/[your-username]/DeObsBench}
}
```

## Disclaimer

This tool is designed for cybersecurity research and education. The malware samples used are for legitimate research purposes only. Users are responsible for complying with applicable laws and regulations.
