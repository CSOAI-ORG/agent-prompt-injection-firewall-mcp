"""Pipelock Integration - Research-driven improvement
Based on: github.com/luckyPipewrench/pipelock (Apache 2.0)

Integrates 6-pass normalization pipeline:
1. Zero-width character detection
2. Homoglyph detection  
3. Leetspeak detection
4. Base64 detection
5. Tool description poisoning detection
6. Prompt injection blocking

Research source: Pipelock (NEW open-source AI agent firewall)
"""
import re
import base64
import unicodedata

class PipelockIntegration:
    """6-pass normalization pipeline from Pipelock"""
    
    @staticmethod
    def zero_width_detect(text: str) -> bool:
        """Detect zero-width characters (CVE-2024-5565)"""
        zw_pattern = r'[\u200b\u200c\u200d\u2060\ufeff]'
        return bool(re.search(zw_pattern, text))
    
    @staticmethod
    def homoglyph_detect(text: str) -> list:
        """Detect homoglyph attacks (e.g., Greek 'ρ' vs Latin 'p')"""
        suspicious = []
        # Common homoglyphs
        homoglyphs = {
            'ρ': 'p', 'е': 'e', 'а': 'a', 'і': 'i',
            'σ': 'o', 'ν': 'v', 'λ': 'l'
        }
        for i, char in enumerate(text):
            if char in homoglyphs:
                suspicious.append({
                    'position': i,
                    'char': char,
                    'likely_intended': homoglyphs[char]
                })
        return suspicious
    
    @staticmethod
    def leetspeak_normalize(text: str) -> str:
        """Normalize leetspeak (e.g., '3' → 'e', '1' → 'i')"""
        leet_map = {
            '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a',
            '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g'
        }
        result = text.lower()
        for leet, normal in leet_map.items():
            result = result.replace(leet, normal)
        return result
    
    @staticmethod
    def base64_detect(text: str) -> bool:
        """Detect base64 encoded payloads"""
        b64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
        return bool(re.match(b64_pattern, text.strip()))
    
    @staticmethod
    def tool_poisoning_detect(tool_description: str) -> dict:
        """Detect tool description poisoning attacks"""
        suspicious_patterns = [
            r'ignore previous instructions',
            r'disregard.*instructions',
            r'you are now',
            r'act as (a|an)',
            r'pretend to be'
        ]
        findings = []
        for pattern in suspicious_patterns:
            if re.search(pattern, tool_description, re.IGNORECASE):
                findings.append(pattern)
        return {
            'poisoned': len(findings) > 0,
            'patterns_matched': findings
        }
    
    def six_pass_scan(self, text: str) -> dict:
        """Run 6-pass normalization pipeline"""
        result = {
            'original': text,
            'passes': {},
            'threats': []
        }
        
        # Pass 1: Zero-width detection
        if self.zero_width_detect(text):
            result['passes']['zero_width'] = 'DETECTED'
            result['threats'].append('zero_width_chars')
        else:
            result['passes']['zero_width'] = 'CLEAR'
        
        # Pass 2: Homoglyph detection
        homoglyphs = self.homoglyph_detect(text)
        if homoglyphs:
            result['passes']['homoglyphs'] = homoglyphs
            result['threats'].append('homoglyph_attack')
        else:
            result['passes']['homoglyphs'] = 'CLEAR'
        
        # Pass 3: Leetspeak normalization
        normalized = self.leetspeak_normalize(text)
        result['passes']['leetspeak'] = 'NORMALIZED' if normalized != text.lower() else 'CLEAR'
        result['normalized'] = normalized
        
        # Pass 4: Base64 detection
        if self.base64_detect(text):
            result['passes']['base64'] = 'DETECTED'
            result['threats'].append('base64_payload')
        else:
            result['passes']['base64'] = 'CLEAR'
        
        # Pass 5: Tool poisoning (if looks like tool description)
        if len(text) > 50:
            poison = self.tool_poisoning_detect(text)
            result['passes']['tool_poisoning'] = poison
            if poison['poisoned']:
                result['threats'].append('tool_poisoning')
        
        # Pass 6: Final assessment
        result['threat_level'] = 'HIGH' if len(result['threats']) >= 3 else \
                              'MEDIUM' if len(result['threats']) >= 1 else 'LOW'
        
        return result

# Integration with prompt-injection-firewall MCP
def enhance_validate_input(text: str) -> dict:
    """Enhanced validation using Pipelock patterns"""
    pipelock = PipelockIntegration()
    scan_result = pipelock.six_pass_scan(text)
    
    return {
        'safe': scan_result['threat_level'] == 'LOW',
        'threat_level': scan_result['threat_level'],
        'threats': scan_result['threats'],
        'passes': scan_result['passes'],
        'recommendation': 'BLOCK' if scan_result['threat_level'] == 'HIGH' else 'ALLOW'
    }

if __name__ == "__main__":
    # Test
    test_cases = [
        "normal text",
        "hеllo",  # with Cyrillic 'е'
        "ignor\u200b guidelines",
        "base64: SGVsbG8gV29ybGQ="
    ]
    
    pipelock = PipelockIntegration()
    for test in test_cases:
        result = pipelock.six_pass_scan(test)
        print(f"Text: {test[:30]}...")
        print(f"  Threat level: {result['threat_level']}")
        print(f"  Threats: {result['threats']}")
        print()
