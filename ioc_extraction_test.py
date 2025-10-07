#!/usr/bin/env python3
"""
IOC Extraction Test Script for DeObsBench

This script tests various LLM models' ability to deobfuscate malware and extract
Indicators of Compromise (IOCs) from PowerShell samples using OpenRouter API.
"""

import os
import json
import yaml
import time
import logging
import argparse
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, fields
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from database import DeObsDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ioc_extraction.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def serialize_dataclass(obj):
    """Custom serialization function for dataclasses with nested objects"""
    if hasattr(obj, '__dataclass_fields__'):
        return asdict(obj)
    elif isinstance(obj, list):
        return [serialize_dataclass(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: serialize_dataclass(v) for k, v in obj.items()}
    else:
        return obj

@dataclass
class IOCResult:
    """Represents a single IOC extraction result"""
    type: str
    original_value: str
    decoded_value: str
    description: str

@dataclass
class SampleResult:
    """Represents results for a single sample"""
    sample_name: str
    model_name: str
    iocs: List[IOCResult]
    processing_time: float
    success: bool
    error_message: Optional[str] = None
    ground_truth_match: Optional[Dict[str, Any]] = None

@dataclass
class ModelResults:
    """Represents results for a single model across all samples"""
    model_name: str
    total_samples: int
    successful_samples: int
    failed_samples: int
    total_processing_time: float
    average_processing_time: float
    sample_results: List[SampleResult]
    ioc_statistics: Dict[str, Any]

class OpenRouterClient:
    """Client for interacting with OpenRouter API"""
    
    def __init__(self, api_key: str, base_url: str = "https://openrouter.ai/api/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def make_request(self, model: str, messages: List[Dict[str, str]], 
                    temperature: float = 0.1, max_tokens: int = 2000, 
                    timeout: int = 60, use_structured_output: bool = True) -> Dict[str, Any]:
        """Make a request to OpenRouter API with optional structured output"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/DeObsBench",
            "X-Title": "DeObsBench IOC Extraction"
        }
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        # Add structured output if requested
        if use_structured_output:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "ioc_extraction",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "iocs": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "type": {
                                            "type": "string",
                                            "description": "The type of IOC (url, domain, ip, file_name, etc.)"
                                        },
                                        "original_value": {
                                            "type": "string",
                                            "description": "The original obfuscated value as found in the script"
                                        },
                                        "decoded_value": {
                                            "type": "string",
                                            "description": "The decoded/cleaned value after deobfuscation"
                                        },
                                        "description": {
                                            "type": "string",
                                            "description": "Brief description of what this IOC represents"
                                        }
                                    },
                                    "required": ["type", "original_value", "decoded_value", "description"],
                                    "additionalProperties": False
                                }
                            }
                        },
                        "required": ["iocs"],
                        "additionalProperties": False
                    }
                }
            }
        
        try:
            response = self.session.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                # Check if it's a structured output error
                try:
                    error_data = e.response.json()
                    if 'error' in error_data and 'structured output' in str(error_data['error']).lower():
                        logger.warning(f"Model {model} doesn't support structured output, falling back to text parsing")
                        # Retry without structured output
                        payload.pop('response_format', None)
                        response = self.session.post(
                            f"{self.base_url}/chat/completions",
                            headers=headers,
                            json=payload,
                            timeout=timeout
                        )
                        response.raise_for_status()
                        return response.json()
                except:
                    pass
            logger.error(f"API request failed: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise

class IOCExtractor:
    """Main class for IOC extraction testing"""
    
    def __init__(self, config_path: str = "config.yaml", prompts_path: str = "prompts.yaml", 
                 db_path: str = "deobsbench.db"):
        self.config = self._load_config(config_path)
        self.prompts = self._load_prompts(prompts_path)
        self.openrouter_client = None
        self.sample_index = self._load_sample_index()
        self.db = DeObsDatabase(db_path)
        self.current_run_id = None
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
    
    def _load_prompts(self, prompts_path: str) -> Dict[str, Any]:
        """Load prompts from YAML file"""
        try:
            with open(prompts_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load prompts: {e}")
            raise
    
    def _load_sample_index(self) -> Dict[str, Any]:
        """Load sample index from JSON file"""
        try:
            with open(self.config['samples']['index_file'], 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load sample index: {e}")
            raise
    
    def _load_models(self, models_path: str) -> List[str]:
        """Load list of models to test"""
        try:
            with open(models_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            raise
    
    def _setup_openrouter_client(self):
        """Setup OpenRouter client with API key from environment or .env file"""
        api_key = os.getenv('OPENROUTER_API_KEY')
        
        # If not found in environment, try to load from .env file
        if not api_key:
            try:
                from dotenv import load_dotenv
                load_dotenv()
                api_key = os.getenv('OPENROUTER_API_KEY')
            except ImportError:
                logger.warning("python-dotenv not installed, cannot load .env file")
        
        if not api_key:
            raise ValueError(
                "OPENROUTER_API_KEY not found. Please set it as an environment variable "
                "or add it to a .env file. See env.template for reference."
            )
        
        if api_key == 'your_openrouter_api_key_here':
            raise ValueError(
                "Please set your actual OpenRouter API key. The template value was found. "
                "Edit .env file and replace 'your_openrouter_api_key_here' with your real API key."
            )
        
        self.openrouter_client = OpenRouterClient(api_key)
    
    def _get_enabled_categories(self) -> List[str]:
        """Get list of enabled IOC categories"""
        return [cat for cat, config in self.config['ioc_categories'].items() 
                if config.get('enabled', False)]
    
    def _format_categories_text(self) -> str:
        """Format enabled categories for prompt"""
        enabled_categories = self._get_enabled_categories()
        categories_text = []
        
        for category in enabled_categories:
            config = self.config['ioc_categories'][category]
            examples = config.get('examples', [])
            examples_str = ', '.join(f'"{ex}"' for ex in examples)
            categories_text.append(f"- {category.upper()}: {examples_str}")
        
        return '\n'.join(categories_text)
    
    def _format_type_examples(self) -> str:
        """Format type examples for prompt"""
        enabled_categories = self._get_enabled_categories()
        return ', '.join(enabled_categories)
    
    def _read_sample_file(self, sample_path: str) -> str:
        """Read sample file content"""
        try:
            with open(sample_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read sample file {sample_path}: {e}")
            raise
    
    def _extract_iocs_from_response(self, response_text: str) -> List[IOCResult]:
        """Extract IOCs from model response (structured output or fallback)"""
        try:
            # Try to parse as JSON (structured output should always be valid JSON)
            response_data = json.loads(response_text)
            iocs = []
            
            # Handle structured output format
            if 'iocs' in response_data:
                for ioc_data in response_data['iocs']:
                    ioc = IOCResult(
                        type=ioc_data.get('type', 'unknown'),
                        original_value=ioc_data.get('original_value', ''),
                        decoded_value=ioc_data.get('decoded_value', ''),
                        description=ioc_data.get('description', '')
                    )
                    iocs.append(ioc)
            else:
                # Fallback: check if response is a list of IOCs directly
                if isinstance(response_data, list):
                    for ioc_data in response_data:
                        ioc = IOCResult(
                            type=ioc_data.get('type', 'unknown'),
                            original_value=ioc_data.get('original_value', ''),
                            decoded_value=ioc_data.get('decoded_value', ''),
                            description=ioc_data.get('description', '')
                        )
                        iocs.append(ioc)
            
            logger.debug(f"Successfully extracted {len(iocs)} IOCs from structured response")
            return iocs
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse model response as JSON: {e}")
            logger.warning("Attempting text extraction fallback")
            # Fallback: try to extract IOCs from text response
            return self._extract_iocs_from_text(response_text)
        except Exception as e:
            logger.error(f"Unexpected error parsing response: {e}")
            return self._extract_iocs_from_text(response_text)
    
    def _extract_iocs_from_text(self, text: str) -> List[IOCResult]:
        """Fallback method to extract IOCs from text response"""
        iocs = []
        
        # First, try to extract JSON from markdown code blocks
        json_content = self._extract_json_from_markdown(text)
        if json_content:
            try:
                response_data = json.loads(json_content)
                if 'iocs' in response_data:
                    for ioc_data in response_data['iocs']:
                        ioc = IOCResult(
                            type=ioc_data.get('type', 'unknown'),
                            original_value=ioc_data.get('original_value', ''),
                            decoded_value=ioc_data.get('decoded_value', ''),
                            description=ioc_data.get('description', '')
                        )
                        iocs.append(ioc)
                    logger.debug(f"Successfully extracted {len(iocs)} IOCs from markdown-wrapped JSON")
                    return iocs
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON from markdown: {e}")
        
        # Fallback to simple text parsing
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in ['url:', 'domain:', 'ip:', 'file:']):
                # Simple extraction - this could be improved
                parts = line.split(':', 1)
                if len(parts) == 2:
                    ioc_type = parts[0].strip().lower()
                    value = parts[1].strip()
                    ioc = IOCResult(
                        type=ioc_type,
                        original_value=value,
                        decoded_value=value,
                        description=f"Extracted from text: {ioc_type}"
                    )
                    iocs.append(ioc)
        
        return iocs
    
    def _extract_json_from_markdown(self, text: str) -> Optional[str]:
        """Extract JSON content from markdown code blocks"""
        import re
        
        # Look for JSON code blocks
        json_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
        matches = re.findall(json_pattern, text, re.DOTALL)
        
        if matches:
            # Return the first JSON block found
            return matches[0]
        
        # Also try to find JSON without code blocks
        json_pattern = r'\{[^{}]*"iocs"[^{}]*\}'
        matches = re.findall(json_pattern, text, re.DOTALL)
        
        if matches:
            return matches[0]
        
        return None
    
    def _compare_with_ground_truth(self, sample_name: str, extracted_iocs: List[IOCResult]) -> Dict[str, Any]:
        """Compare extracted IOCs with ground truth, focusing on obfuscated IOCs"""
        # Find sample in index
        sample_data = None
        for sample in self.sample_index['samples']:
            if sample['name'] == sample_name:
                sample_data = sample
                break
        
        if not sample_data or 'indicators' not in sample_data:
            return {
                'ground_truth_available': False,
                'total_ground_truth': 0,
                'total_obfuscated_gt': 0,
                'total_extracted': len(extracted_iocs),
                'matches': 0,
                'obfuscated_matches': 0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'obfuscated_precision': 0.0,
                'obfuscated_recall': 0.0,
                'obfuscated_f1_score': 0.0,
                'detailed_matches': [],
                'missed_obfuscated': [],
                'false_positives': []
            }
        
        # Separate obfuscated and non-obfuscated ground truth indicators
        obfuscated_indicators = []
        non_obfuscated_indicators = []
        
        for ind in sample_data['indicators']:
            if ind.get('obfuscated', 'False').lower() == 'true':
                obfuscated_indicators.append(ind['indicator'])
            else:
                non_obfuscated_indicators.append(ind['indicator'])
        
        all_ground_truth = obfuscated_indicators + non_obfuscated_indicators
        extracted_values = [ioc.decoded_value for ioc in extracted_iocs if ioc.decoded_value]
        
        # Track detailed matches
        detailed_matches = []
        matched_gt = set()
        matched_extracted = set()
        
        # Check each extracted IOC against ground truth
        # Use a more sophisticated matching algorithm that prioritizes exact matches
        for i, extracted in enumerate(extracted_values):
            matched = False
            best_match_idx = -1
            best_match_score = 0
            
            # First pass: look for exact matches
            for j, gt in enumerate(all_ground_truth):
                if j in matched_gt:  # Skip already matched ground truth
                    continue
                if extracted.strip().lower() == gt.strip().lower():
                    detailed_matches.append({
                        'extracted': extracted,
                        'ground_truth': gt,
                        'is_obfuscated': gt in obfuscated_indicators,
                        'extracted_ioc': extracted_iocs[i],
                        'match_type': 'exact'
                    })
                    matched_gt.add(j)
                    matched_extracted.add(i)
                    matched = True
                    break
            
            # Second pass: look for partial matches if no exact match found
            if not matched:
                for j, gt in enumerate(all_ground_truth):
                    if j in matched_gt:  # Skip already matched ground truth
                        continue
                    if self._ioc_matches(extracted, gt):
                        # Calculate match score (prefer longer matches)
                        match_score = min(len(extracted), len(gt)) / max(len(extracted), len(gt))
                        if match_score > best_match_score:
                            best_match_score = match_score
                            best_match_idx = j
            
            # Use the best partial match if found
            if not matched and best_match_idx >= 0:
                gt = all_ground_truth[best_match_idx]
                detailed_matches.append({
                    'extracted': extracted,
                    'ground_truth': gt,
                    'is_obfuscated': gt in obfuscated_indicators,
                    'extracted_ioc': extracted_iocs[i],
                    'match_type': 'partial'
                })
                matched_gt.add(best_match_idx)
                matched_extracted.add(i)
                matched = True
            
            if not matched:
                detailed_matches.append({
                    'extracted': extracted,
                    'ground_truth': None,
                    'is_obfuscated': False,
                    'extracted_ioc': extracted_iocs[i],
                    'is_false_positive': True,
                    'match_type': 'none'
                })
        
        # Count matches
        total_matches = len(matched_gt)
        obfuscated_matches = sum(1 for match in detailed_matches 
                               if match.get('is_obfuscated', False) and match.get('ground_truth') is not None)
        
        # Calculate precision and recall
        precision = total_matches / len(extracted_values) if extracted_values else 0.0
        recall = total_matches / len(all_ground_truth) if all_ground_truth else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Calculate obfuscated-specific metrics
        obfuscated_precision = obfuscated_matches / len(extracted_values) if extracted_values else 0.0
        obfuscated_recall = obfuscated_matches / len(obfuscated_indicators) if obfuscated_indicators else 0.0
        obfuscated_f1_score = 2 * (obfuscated_precision * obfuscated_recall) / (obfuscated_precision + obfuscated_recall) if (obfuscated_precision + obfuscated_recall) > 0 else 0.0
        
        # Find missed obfuscated IOCs
        missed_obfuscated = []
        for i, gt in enumerate(obfuscated_indicators):
            if i not in matched_gt:
                missed_obfuscated.append(gt)
        
        # Find false positives (extracted IOCs that don't match any ground truth)
        false_positives = [match['extracted'] for match in detailed_matches if match.get('is_false_positive', False)]
        
        return {
            'ground_truth_available': True,
            'total_ground_truth': len(all_ground_truth),
            'total_obfuscated_gt': len(obfuscated_indicators),
            'total_extracted': len(extracted_iocs),
            'matches': total_matches,
            'obfuscated_matches': obfuscated_matches,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'obfuscated_precision': obfuscated_precision,
            'obfuscated_recall': obfuscated_recall,
            'obfuscated_f1_score': obfuscated_f1_score,
            'detailed_matches': detailed_matches,
            'missed_obfuscated': missed_obfuscated,
            'false_positives': false_positives
        }
    
    def _ioc_matches(self, extracted: str, ground_truth: str) -> bool:
        """Check if an extracted IOC matches ground truth with various matching strategies"""
        if not extracted or not ground_truth:
            return False
        
        # Normalize strings for comparison
        extracted_norm = extracted.strip().lower()
        gt_norm = ground_truth.strip().lower()
        
        # Exact match (highest priority)
        if extracted_norm == gt_norm:
            return True
        
        # Check for URL components (domain, path, etc.) - more specific matching
        if self._url_components_match(extracted_norm, gt_norm):
            return True
        
        # Check for filename matches (case insensitive) - more specific matching
        if self._filename_matches(extracted_norm, gt_norm):
            return True
        
        # Check if one contains the other (for partial matches) - but be more restrictive
        # Only allow this if one is significantly longer than the other (avoid false positives)
        if len(extracted_norm) > 5 and len(gt_norm) > 5:  # Both must be substantial strings
            if extracted_norm in gt_norm and len(extracted_norm) >= len(gt_norm) * 0.7:
                return True
            if gt_norm in extracted_norm and len(gt_norm) >= len(extracted_norm) * 0.7:
                return True
        
        return False
    
    def _url_components_match(self, extracted: str, ground_truth: str) -> bool:
        """Check if URL components match"""
        try:
            from urllib.parse import urlparse
            
            # Parse URLs
            ext_parsed = urlparse(extracted if extracted.startswith(('http://', 'https://')) else f'http://{extracted}')
            gt_parsed = urlparse(ground_truth if ground_truth.startswith(('http://', 'https://')) else f'http://{ground_truth}')
            
            # Compare domains
            if ext_parsed.netloc and gt_parsed.netloc:
                if ext_parsed.netloc == gt_parsed.netloc:
                    return True
            
            # Compare paths
            if ext_parsed.path and gt_parsed.path:
                if ext_parsed.path == gt_parsed.path:
                    return True
                    
        except:
            pass
        
        return False
    
    def _filename_matches(self, extracted: str, ground_truth: str) -> bool:
        """Check if filenames match"""
        import os
        
        ext_filename = os.path.basename(extracted)
        gt_filename = os.path.basename(ground_truth)
        
        return ext_filename == gt_filename
    
    def process_sample(self, sample_data: Dict[str, Any], model: str) -> SampleResult:
        """Process a single sample with a given model"""
        start_time = time.time()
        sample_result_id = None
        
        try:
            # Read sample file
            sample_content = self._read_sample_file(sample_data['path'])
            
            # Prepare prompt
            categories_text = self._format_categories_text()
            type_examples = self._format_type_examples()
            
            user_prompt = self.prompts['ioc_extraction']['user_prompt_template'].format(
                sample_name=sample_data['name'],
                file_content=sample_content,
                categories_text=categories_text,
                type_examples_text=type_examples
            )
            
            # Create database record for this sample (after we have the user prompt)
            sample_result_id = None
            if self.current_run_id:
                sample_result_id = self.db.create_sample_result(
                    run_id=self.current_run_id,
                    model_name=model,
                    sample_name=sample_data['name'],
                    sample_path=sample_data['path'],
                    prompt_system=self.prompts['ioc_extraction']['system_role'],
                    prompt_user=user_prompt
                )
            
            messages = [
                {"role": "system", "content": self.prompts['ioc_extraction']['system_role']},
                {"role": "user", "content": user_prompt}
            ]
            
            # Make API request with retry logic for empty responses
            max_retries = self.config['processing'].get('max_retries', 3)
            response = None
            response_text = ""
            
            for attempt in range(max_retries):
                try:
                    response = self.openrouter_client.make_request(
                        model=model,
                        messages=messages,
                        temperature=self.config['openrouter']['temperature'],
                        max_tokens=self.config['openrouter']['max_tokens'],
                        timeout=self.config['openrouter']['timeout'],
                        use_structured_output=self.config['openrouter'].get('use_structured_output', True)
                    )
                    
                    # Check if we got a valid response
                    response_text = response['choices'][0]['message']['content']
                    if response_text and response_text.strip():
                        logger.debug(f"Got valid response on attempt {attempt + 1}")
                        break
                    else:
                        logger.warning(f"Empty response on attempt {attempt + 1}/{max_retries} for model {model}")
                        if attempt < max_retries - 1:
                            # Wait before retrying
                            retry_delay = self.config['processing'].get('retry_delay', 2)
                            time.sleep(retry_delay)
                        else:
                            logger.error(f"All {max_retries} attempts failed for model {model} - no response content")
                            
                except Exception as e:
                    logger.warning(f"API request failed on attempt {attempt + 1}/{max_retries}: {e}")
                    if attempt < max_retries - 1:
                        retry_delay = self.config['processing'].get('retry_delay', 2)
                        time.sleep(retry_delay)
                    else:
                        raise
            
            # Extract IOCs from response
            iocs = self._extract_iocs_from_response(response_text) if response_text else []
            
            # Determine if the request was successful
            success = bool(response_text and response_text.strip())
            
            # Compare with ground truth
            ground_truth_match = self._compare_with_ground_truth(sample_data['name'], iocs)
            
            processing_time = time.time() - start_time
            
            # Update database with results
            if sample_result_id:
                iocs_dict = [serialize_dataclass(ioc) for ioc in iocs]
                self.db.update_sample_result(
                    sample_result_id=sample_result_id,
                    response_text=response_text,
                    response_json=json.dumps(response) if response else "{}",
                    iocs_extracted=iocs_dict,
                    success=success,
                    processing_time=processing_time,
                    error_message="No response content after all retries" if not success else None,
                    ground_truth_match=ground_truth_match
                )
                
                # Add individual IOC results only if we have IOCs
                if iocs:
                    self.db.add_ioc_results(sample_result_id, iocs_dict)
            
            return SampleResult(
                sample_name=sample_data['name'],
                model_name=model,
                iocs=iocs,
                processing_time=processing_time,
                success=success,
                error_message="No response content after all retries" if not success else None,
                ground_truth_match=ground_truth_match
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Failed to process sample {sample_data['name']} with model {model}: {e}")
            
            # Create database record for failed sample if not already created
            if self.current_run_id and not sample_result_id:
                try:
                    # Try to prepare the prompt for database storage
                    sample_content = self._read_sample_file(sample_data['path'])
                    categories_text = self._format_categories_text()
                    type_examples = self._format_type_examples()
                    user_prompt = self.prompts['ioc_extraction']['user_prompt_template'].format(
                        sample_name=sample_data['name'],
                        file_content=sample_content,
                        categories_text=categories_text,
                        type_examples_text=type_examples
                    )
                    
                    sample_result_id = self.db.create_sample_result(
                        run_id=self.current_run_id,
                        model_name=model,
                        sample_name=sample_data['name'],
                        sample_path=sample_data['path'],
                        prompt_system=self.prompts['ioc_extraction']['system_role'],
                        prompt_user=user_prompt
                    )
                except Exception as db_error:
                    logger.warning(f"Failed to create database record for failed sample: {db_error}")
            
            # Update database with error
            if sample_result_id:
                self.db.update_sample_result(
                    sample_result_id=sample_result_id,
                    response_text="",
                    response_json="",
                    iocs_extracted=[],
                    success=False,
                    processing_time=processing_time,
                    error_message=str(e)
                )
            
            return SampleResult(
                sample_name=sample_data['name'],
                model_name=model,
                iocs=[],
                processing_time=processing_time,
                success=False,
                error_message=str(e)
            )
    
    def test_model(self, model: str, max_samples: Optional[int] = None) -> ModelResults:
        """Test a single model on all samples"""
        logger.info(f"Testing model: {model}")
        
        # Create model test record in database
        if self.current_run_id:
            self.db.create_model_test(
                run_id=self.current_run_id,
                model_name=model,
                total_samples=0  # Will be updated below
            )
        
        # Filter samples based on configuration
        samples_to_process = []
        for sample in self.sample_index['samples']:
            if self.config['samples']['only_process_with_indicators']:
                if 'indicators' not in sample or not sample['indicators']:
                    continue
            
            samples_to_process.append(sample)
            
            if max_samples and len(samples_to_process) >= max_samples:
                break
        
        logger.info(f"Processing {len(samples_to_process)} samples with model {model}")
        
        sample_results = []
        total_processing_time = 0
        successful_samples = 0
        failed_samples = 0
        
        for i, sample in enumerate(samples_to_process, 1):
            logger.info(f"Processing sample {i}/{len(samples_to_process)}: {sample['name']}")
            
            # Rate limiting
            if i > 1:
                time.sleep(self.config['processing']['rate_limit_delay'])
            
            result = self.process_sample(sample, model)
            sample_results.append(result)
            
            total_processing_time += result.processing_time
            
            if result.success:
                successful_samples += 1
                logger.info(f"Successfully processed {sample['name']} in {result.processing_time:.2f}s")
            else:
                failed_samples += 1
                logger.error(f"Failed to process {sample['name']}: {result.error_message}")
        
        # Calculate statistics
        average_processing_time = total_processing_time / len(samples_to_process) if samples_to_process else 0
        
        # Calculate IOC statistics
        all_iocs = []
        for result in sample_results:
            if result.success:
                all_iocs.extend(result.iocs)
        
        ioc_type_counts = {}
        for ioc in all_iocs:
            ioc_type_counts[ioc.type] = ioc_type_counts.get(ioc.type, 0) + 1
        
        ioc_statistics = {
            'total_iocs_extracted': len(all_iocs),
            'ioc_type_distribution': ioc_type_counts,
            'average_iocs_per_sample': len(all_iocs) / successful_samples if successful_samples > 0 else 0
        }
        
        # Update model test record in database
        if self.current_run_id:
            self.db.update_model_test(
                run_id=self.current_run_id,
                model_name=model,
                successful_samples=successful_samples,
                failed_samples=failed_samples,
                total_processing_time=total_processing_time,
                average_processing_time=average_processing_time,
                total_iocs_extracted=len(all_iocs),
                average_iocs_per_sample=ioc_statistics['average_iocs_per_sample'],
                ioc_type_distribution=ioc_type_counts
            )
        
        return ModelResults(
            model_name=model,
            total_samples=len(samples_to_process),
            successful_samples=successful_samples,
            failed_samples=failed_samples,
            total_processing_time=total_processing_time,
            average_processing_time=average_processing_time,
            sample_results=sample_results,
            ioc_statistics=ioc_statistics
        )
    
    def run_tests(self, models_path: str = "models.txt", max_samples: Optional[int] = None, 
                  output_dir: str = "reports") -> Dict[str, ModelResults]:
        """Run tests on all models"""
        logger.info("Starting IOC extraction tests")
        
        # Setup
        self._setup_openrouter_client()
        models = self._load_models(models_path)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize test run in database
        run_id = str(uuid.uuid4())
        self.current_run_id = run_id
        
        # Calculate total samples
        total_samples = 0
        for sample in self.sample_index['samples']:
            if self.config['samples']['only_process_with_indicators']:
                if 'indicators' not in sample or not sample['indicators']:
                    continue
            total_samples += 1
            if max_samples and total_samples >= max_samples:
                break
        
        self.db.create_test_run(
            run_id=run_id,
            total_models=len(models),
            total_samples=total_samples,
            config=self.config
        )
        
        logger.info(f"Test run ID: {run_id}")
        
        all_results = {}
        
        try:
            for model in models:
                try:
                    logger.info(f"Testing model: {model}")
                    results = self.test_model(model, max_samples)
                    all_results[model] = results
                    
                    # Save individual model results
                    model_output_file = os.path.join(output_dir, f"{model.replace('/', '_')}_results.json")
                    with open(model_output_file, 'w') as f:
                        json.dump(serialize_dataclass(results), f, indent=2, default=str)
                    
                    logger.info(f"Model {model} completed: {results.successful_samples}/{results.total_samples} samples successful")
                    
                except Exception as e:
                    logger.error(f"Failed to test model {model}: {e}")
                    continue
            
            # Update test run status
            self.db.update_test_run(run_id, status='completed')
            
            # Save combined results
            combined_output_file = os.path.join(output_dir, "combined_results.json")
            with open(combined_output_file, 'w') as f:
                json.dump({model: serialize_dataclass(results) for model, results in all_results.items()}, 
                         f, indent=2, default=str)
            
            # Generate summary report
            self._generate_summary_report(all_results, output_dir)
            
            # Export database results
            db_export_file = os.path.join(output_dir, f"database_export_{run_id}.json")
            self.db.export_to_json(run_id, db_export_file)
            
            logger.info("All tests completed")
            logger.info(f"Database export: {db_export_file}")
            
        except Exception as e:
            logger.error(f"Test run failed: {e}")
            self.db.update_test_run(run_id, status='failed')
            raise
        
        finally:
            self.current_run_id = None
        
        return all_results
    
    def _generate_summary_report(self, results: Dict[str, ModelResults], output_dir: str):
        """Generate a summary report comparing all models"""
        report_path = os.path.join(output_dir, "summary_report.md")
        
        with open(report_path, 'w') as f:
            f.write("# IOC Extraction Test Results Summary\n\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Overall statistics
            f.write("## Overall Statistics\n\n")
            f.write("| Model | Samples | Success | Failed | Success Rate | Avg Time (s) | Total IOCs | Obsc. F1 |\n")
            f.write("|-------|---------|---------|--------|--------------|--------------|------------|----------|\n")
            
            for model, result in results.items():
                success_rate = (result.successful_samples / result.total_samples * 100) if result.total_samples > 0 else 0
                
                # Calculate average obfuscated F1 score for this model
                obfuscated_f1_scores = []
                for sample_result in result.sample_results:
                    if sample_result.success and sample_result.ground_truth_match:
                        obfuscated_f1 = sample_result.ground_truth_match.get('obfuscated_f1_score', 0.0)
                        if obfuscated_f1 > 0:
                            obfuscated_f1_scores.append(obfuscated_f1)
                
                avg_obfuscated_f1 = sum(obfuscated_f1_scores) / len(obfuscated_f1_scores) if obfuscated_f1_scores else 0.0
                
                f.write(f"| {model} | {result.total_samples} | {result.successful_samples} | {result.failed_samples} | {success_rate:.1f}% | {result.average_processing_time:.2f} | {result.ioc_statistics['total_iocs_extracted']} | {avg_obfuscated_f1:.3f} |\n")
            
            # Detailed results per model
            f.write("\n## Detailed Results by Model\n\n")
            
            for model, result in results.items():
                f.write(f"### {model}\n\n")
                f.write(f"- **Total Samples**: {result.total_samples}\n")
                f.write(f"- **Successful**: {result.successful_samples}\n")
                f.write(f"- **Failed**: {result.failed_samples}\n")
                f.write(f"- **Success Rate**: {(result.successful_samples / result.total_samples * 100) if result.total_samples > 0 else 0:.1f}%\n")
                f.write(f"- **Average Processing Time**: {result.average_processing_time:.2f}s\n")
                f.write(f"- **Total IOCs Extracted**: {result.ioc_statistics['total_iocs_extracted']}\n")
                f.write(f"- **Average IOCs per Sample**: {result.ioc_statistics['average_iocs_per_sample']:.2f}\n")
                
                # IOC type distribution
                f.write("\n**IOC Type Distribution:**\n")
                for ioc_type, count in result.ioc_statistics['ioc_type_distribution'].items():
                    f.write(f"- {ioc_type}: {count}\n")
                
                # Obfuscated IOC analysis
                f.write("\n**Obfuscated IOC Analysis:**\n")
                obfuscated_stats = {
                    'total_obfuscated_gt': 0,
                    'obfuscated_matches': 0,
                    'obfuscated_precision': 0.0,
                    'obfuscated_recall': 0.0,
                    'obfuscated_f1_score': 0.0
                }
                
                for sample_result in result.sample_results:
                    if sample_result.success and sample_result.ground_truth_match:
                        gt = sample_result.ground_truth_match
                        obfuscated_stats['total_obfuscated_gt'] += gt.get('total_obfuscated_gt', 0)
                        obfuscated_stats['obfuscated_matches'] += gt.get('obfuscated_matches', 0)
                        obfuscated_stats['obfuscated_precision'] += gt.get('obfuscated_precision', 0.0)
                        obfuscated_stats['obfuscated_recall'] += gt.get('obfuscated_recall', 0.0)
                        obfuscated_stats['obfuscated_f1_score'] += gt.get('obfuscated_f1_score', 0.0)
                
                successful_samples = result.successful_samples
                if successful_samples > 0:
                    f.write(f"- Total Obfuscated IOCs in Ground Truth: {obfuscated_stats['total_obfuscated_gt']}\n")
                    f.write(f"- Obfuscated IOCs Successfully Extracted: {obfuscated_stats['obfuscated_matches']}\n")
                    f.write(f"- Average Obfuscated Precision: {obfuscated_stats['obfuscated_precision']/successful_samples:.3f}\n")
                    f.write(f"- Average Obfuscated Recall: {obfuscated_stats['obfuscated_recall']/successful_samples:.3f}\n")
                    f.write(f"- Average Obfuscated F1 Score: {obfuscated_stats['obfuscated_f1_score']/successful_samples:.3f}\n")
                
                f.write("\n")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Test LLM models for IOC extraction from malware samples")
    parser.add_argument("--models", default="models.txt", help="Path to models file")
    parser.add_argument("--max-samples", type=int, help="Maximum number of samples to process per model")
    parser.add_argument("--output-dir", default="reports", help="Output directory for results")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--prompts", default="prompts.yaml", help="Path to prompts file")
    
    args = parser.parse_args()
    
    try:
        extractor = IOCExtractor(args.config, args.prompts)
        results = extractor.run_tests(args.models, args.max_samples, args.output_dir)
        
        print(f"\nTesting completed! Results saved to {args.output_dir}/")
        print(f"Summary report: {args.output_dir}/summary_report.md")
        
    except Exception as e:
        logger.error(f"Testing failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
