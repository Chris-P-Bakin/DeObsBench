# IOC Extraction Test Results Summary

Generated on: 2025-09-15 13:32:15

## Overall Statistics

| Model | Samples | Success | Failed | Success Rate | Avg Time (s) | Total IOCs | Obsc. F1 |
|-------|---------|---------|--------|--------------|--------------|------------|----------|
| openai/gpt-4o-mini | 58 | 55 | 3 | 94.8% | 4.04 | 151 | 0.449 |
| openai/gpt-5-mini | 58 | 41 | 17 | 70.7% | 72.79 | 44 | 0.604 |

## Detailed Results by Model

### openai/gpt-4o-mini

- **Total Samples**: 58
- **Successful**: 55
- **Failed**: 3
- **Success Rate**: 94.8%
- **Average Processing Time**: 4.04s
- **Total IOCs Extracted**: 151
- **Average IOCs per Sample**: 2.75

**IOC Type Distribution:**
- url: 62
- file_name: 55
- ip: 10
- domain: 24

**Obfuscated IOC Analysis:**
- Total Obfuscated IOCs in Ground Truth: 200
- Obfuscated IOCs Successfully Extracted: 51
- Average Obfuscated Precision: 0.524
- Average Obfuscated Recall: 0.274
- Average Obfuscated F1 Score: 0.319

### openai/gpt-5-mini

- **Total Samples**: 58
- **Successful**: 41
- **Failed**: 17
- **Success Rate**: 70.7%
- **Average Processing Time**: 72.79s
- **Total IOCs Extracted**: 44
- **Average IOCs per Sample**: 1.07

**IOC Type Distribution:**
- url: 13
- domain: 10
- file_name: 17
- ip: 3
- {"iocs": 1

**Obfuscated IOC Analysis:**
- Total Obfuscated IOCs in Ground Truth: 142
- Obfuscated IOCs Successfully Extracted: 17
- Average Obfuscated Precision: 0.120
- Average Obfuscated Recall: 0.173
- Average Obfuscated F1 Score: 0.133

