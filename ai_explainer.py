"""AI explanations using Ollama.

Generates plain English explanations for threats.
Explanations are cached to reduce API calls.
HIGH/CRITICAL threats use AI by default.
"""

import logging
from typing import Optional
import ollama
from models import Threat
from config import Config

logger = logging.getLogger(__name__)


class AIExplainer:
    """Generates plain English explanations of threats using Ollama."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the AI explainer."""
        self.config = config or Config.get_default()
        self.cache = {}  # Simple in-memory cache
        self.client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Ollama client and verify connection."""
        try:
            # Test connection by trying to list models
            try:
                response = ollama.list()
                # Handle both dict and object response structures
                if hasattr(response, 'models'):
                    models = response.models
                elif isinstance(response, dict):
                    models = response.get('models', [])
                else:
                    models = []
                
                # Extract model names
                model_names = []
                for m in models:
                    if hasattr(m, 'model'):
                        model_names.append(m.model)
                    elif isinstance(m, dict):
                        model_names.append(m.get('model', m.get('name', 'unknown')))
                
                if model_names:
                    logger.info(f"Connected to Ollama. Available models: {model_names}")
                else:
                    logger.info("Connected to Ollama")
            except Exception as list_error:
                logger.debug(f"Could not list models: {list_error}")
                logger.info("Connected to Ollama")
        except Exception as e:
            logger.warning(f"Could not connect to Ollama at {self.config.ollama_endpoint}: {e}")
            logger.warning("AI explanations will be unavailable. Make sure Ollama is running.")
            logger.warning(f"Hint: Start Ollama with 'ollama serve' or check {self.config.ollama_endpoint}")
    
    def explain_threat(self, threat: Threat, use_ai: bool = True) -> Optional[str]:
        """
        Generate a plain English explanation of a threat.
        
        Args:
            threat: Threat object to explain
            use_ai: If True, use AI for HIGH/CRITICAL threats, fallback for others
            
        Returns:
            Plain English explanation or None if generation fails
        """
        # For LOW and MEDIUM severity, use fallback (faster)
        if use_ai and threat.severity in ['LOW', 'MEDIUM']:
            return self._fallback_explanation(threat)
        
        # Check cache first
        cache_key = self._get_cache_key(threat)
        if cache_key in self.cache:
            logger.debug(f"Using cached explanation for threat {threat.id}")
            return self.cache[cache_key]
        
        try:
            if use_ai and threat.severity in ['HIGH', 'CRITICAL']:
                explanation = self._generate_explanation(threat)
            else:
                explanation = self._fallback_explanation(threat)
            
            if explanation:
                self.cache[cache_key] = explanation
            return explanation
        except Exception as e:
            logger.error(f"Error generating AI explanation: {e}")
            return self._fallback_explanation(threat)
    
    def _generate_explanation(self, threat: Threat) -> Optional[str]:
        """Generate explanation using Ollama."""
        # Check if model is specified
        if not self.config.ollama_model:
            logger.warning("No Ollama model specified. Use --model flag or set OLLAMA_MODEL environment variable.")
            return self._fallback_explanation(threat)
        
        try:
            # Build prompt with system instructions
            system_prompt = "You are a cybersecurity expert. Explain security threats in simple, clear language for non-technical users. Keep responses to 2-3 sentences maximum. Be direct and actionable. Only provide the explanation, do not repeat the prompt or include any other text."
            user_prompt = self._build_prompt(threat)
            
            # Call Ollama with system and user prompts
            response = ollama.generate(
                model=self.config.ollama_model,
                system=system_prompt,
                prompt=user_prompt,
                options={
                    'temperature': 0.3,  # Lower temperature for more focused responses
                    'num_predict': 150,  # Limit response length
                }
            )
            
            explanation = response.get('response', '').strip()
            
            # Clean up the response - remove any prompt text that might be included
            if explanation:
                # Remove common prompt patterns that might be echoed
                prompt_patterns = [
                    "Explain what this threat means",
                    "Security Threat Detected",
                    "Type:",
                    "Severity:",
                    "Source:",
                    "Port:",
                    "Issue:",
                    "---",
                    user_prompt[:50] if len(user_prompt) > 50 else user_prompt
                ]
                
                # Try to extract just the explanation part
                lines = explanation.split('\n')
                cleaned_lines = []
                skip_until_explanation = True
                
                for line in lines:
                    line_stripped = line.strip()
                    # Skip empty lines and separator lines
                    if not line_stripped or line_stripped.startswith('---'):
                        continue
                    # Skip lines that look like prompt headers
                    if any(pattern in line_stripped for pattern in ['Type:', 'Severity:', 'Source:', 'Port:', 'Issue:', 'Security Threat']):
                        continue
                    # Skip the instruction line
                    if 'Explain what this threat means' in line_stripped or 'tech-savvy' in line_stripped.lower():
                        skip_until_explanation = False
                        continue
                    # Once we find actual explanation content, keep it
                    if len(line_stripped) > 20 and not any(pattern in line_stripped for pattern in prompt_patterns):
                        skip_until_explanation = False
                        cleaned_lines.append(line_stripped)
                    elif not skip_until_explanation:
                        cleaned_lines.append(line_stripped)
                
                # If we got cleaned content, use it; otherwise use original
                if cleaned_lines:
                    explanation = ' '.join(cleaned_lines).strip()
                else:
                    # Fallback: just take the last meaningful sentence/paragraph
                    explanation = explanation.strip()
                
                if explanation:
                    logger.debug(f"Generated explanation for {threat.event_type} threat")
                    return explanation
                else:
                    logger.warning("Empty explanation after cleaning")
                    return None
            else:
                logger.warning("Empty response from Ollama")
                return None
                
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            # Return a fallback explanation
            return self._fallback_explanation(threat)
    
    def _build_prompt(self, threat: Threat) -> str:
        """Build prompt for Ollama."""
        # Build concise prompt with key details
        details = []
        if threat.source_ip:
            details.append(f"from {threat.source_ip}")
        if threat.dest_port:
            details.append(f"to port {threat.dest_port}")
        details_str = " ".join(details) if details else "from an unknown source"
        
        prompt = f"A {threat.severity} severity {threat.event_type} threat was detected {details_str}. The issue is: {threat.description}. Explain what this means and why it matters in 2-3 simple sentences for a non-technical person."
        
        return prompt
    
    def _fallback_explanation(self, threat: Threat) -> str:
        """Generate a fallback explanation when AI is unavailable."""
        explanations = {
            'alert': f"This is a security alert detected by Suricata. The system identified {threat.description.lower()} which indicates potential malicious activity.",
            'port_scan': f"A port scan was detected from {threat.source_ip or 'an unknown source'}. This means someone is systematically checking which ports are open on your network, which is often a precursor to an attack.",
            'suspicious_port': f"Access to a suspicious port ({threat.dest_port}) was detected. This port is commonly targeted by attackers and may indicate an attempted intrusion.",
            'unusual_traffic': "Unusual network traffic patterns were detected. This could indicate an attack, data exfiltration, or other malicious activity."
        }
        
        return explanations.get(
            threat.event_type,
            f"A {threat.severity.lower()} severity security threat was detected: {threat.description}"
        )
    
    def _get_cache_key(self, threat: Threat) -> str:
        """Generate cache key for a threat."""
        return f"{threat.event_type}:{threat.severity}:{threat.source_ip}:{threat.dest_port}"
    
    def clear_cache(self):
        """Clear the explanation cache."""
        self.cache.clear()
        logger.debug("AI explanation cache cleared")
    
    def explain_batch(self, threats: list[Threat]) -> dict[int, str]:
        """
        Generate explanations for multiple threats.
        
        Args:
            threats: List of Threat objects
            
        Returns:
            Dictionary mapping threat IDs to explanations
        """
        results = {}
        for threat in threats:
            explanation = self.explain_threat(threat)
            if explanation and threat.id:
                results[threat.id] = explanation
        return results
    
    def suggest_suricata_rule(self, threat: Threat) -> Optional[str]:
        """
        Use AI to suggest a Suricata rule based on threat analysis.
        
        Args:
            threat: Threat object to generate rule for
            
        Returns:
            Suricata rule string or None if generation fails
        """
        # Check if model is specified
        if not self.config.ollama_model:
            logger.warning("No Ollama model specified. Use --model flag or set OLLAMA_MODEL environment variable.")
            return self._fallback_suricata_rule(threat)
        
        try:
            # Build prompt for AI
            system_prompt = (
                "You are a Suricata rule expert. Generate a valid Suricata drop rule "
                "based on the threat information. Only output the rule itself, nothing else. "
                "Use the format: drop ip <source_ip> any -> any any (msg:\"reason\"; sid:9000001; rev:1;)"
            )
            
            # Build threat context
            details = []
            if threat.source_ip:
                details.append(f"Source IP: {threat.source_ip}")
            if threat.dest_port:
                details.append(f"Destination Port: {threat.dest_port}")
            details.append(f"Severity: {threat.severity}")
            details.append(f"Type: {threat.event_type}")
            details.append(f"Description: {threat.description}")
            
            user_prompt = (
                f"Generate a Suricata drop rule for this threat:\n"
                f"{', '.join(details)}\n\n"
                f"The rule should block traffic from {threat.source_ip or 'the source'}. "
                f"Use msg to describe why it's being blocked. Only output the rule, no explanation."
            )
            
            # Call Ollama
            response = ollama.generate(
                model=self.config.ollama_model,
                system=system_prompt,
                prompt=user_prompt,
                options={
                    'temperature': 0.2,  # Low temperature for consistent output
                    'num_predict': 100,  # Limit response length
                }
            )
            
            rule = response.get('response', '').strip()
            
            # Clean up response - extract just the rule
            if rule:
                # Remove any explanatory text before/after the rule
                lines = rule.split('\n')
                for line in lines:
                    line = line.strip()
                    # Look for line that starts with 'drop'
                    if line.startswith('drop ') and 'sid:' in line:
                        rule = line
                        break
                
                # Validate basic rule structure
                if self._validate_ai_rule(rule, threat):
                    logger.info(f"AI generated Suricata rule for threat {threat.id}")
                    return rule
                else:
                    logger.warning("AI-generated rule failed validation, using fallback")
                    return self._fallback_suricata_rule(threat)
            else:
                logger.warning("Empty response from AI, using fallback rule")
                return self._fallback_suricata_rule(threat)
                
        except Exception as e:
            logger.error(f"Error generating AI Suricata rule: {e}")
            return self._fallback_suricata_rule(threat)
    
    def _validate_ai_rule(self, rule: str, threat: Threat) -> bool:
        """
        Validate AI-generated Suricata rule.
        
        Args:
            rule: Rule string to validate
            threat: Original threat (for context)
            
        Returns:
            True if valid, False otherwise
        """
        if not rule:
            return False
        
        # Must start with 'drop'
        if not rule.startswith('drop '):
            return False
        
        # Must contain required elements
        required = ['ip', '->', 'msg:', 'sid:', 'rev:']
        if not all(req in rule for req in required):
            return False
        
        # Must contain source IP if available
        if threat.source_ip and threat.source_ip not in rule:
            return False
        
        return True
    
    def _fallback_suricata_rule(self, threat: Threat) -> str:
        """
        Generate a fallback Suricata rule when AI fails.
        
        Args:
            threat: Threat object
            
        Returns:
            Fallback Suricata rule string
        """
        source_ip = threat.source_ip or 'any'
        
        # Sanitize description for rule message
        safe_desc = threat.description.replace('"', "'").replace(';', ',')[:150]
        
        # Generate fallback rule
        rule = (
            f"drop ip {source_ip} any -> any any "
            f"(msg:\"AutoDefender: {safe_desc}\"; "
            f"sid:9000001; rev:1;)"
        )
        
        return rule

