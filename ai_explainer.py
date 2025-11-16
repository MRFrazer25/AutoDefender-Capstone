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
        from urllib.parse import urlparse
        
        # Extract host from endpoint URL
        host = None
        if self.config.ollama_endpoint:
            parsed = urlparse(self.config.ollama_endpoint)
            # Extract host:port (ollama Client expects format like "127.0.0.1:11434")
            host = parsed.netloc or parsed.path
            # If no port specified, default to 11434
            if ':' not in host and parsed.port is None:
                host = f"{host}:11434"
        
        try:
            # Create client with explicit host parameter
            self.client = ollama.Client(host=host) if host else ollama.Client()
            
            # Test connection by trying to list models
            try:
                response = self.client.list()
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
                    self.available_models = model_names
                else:
                    logger.info("Connected to Ollama")
                    self.available_models = []
            except Exception as list_error:
                logger.debug(f"Could not list models: {list_error}")
                logger.info("Connected to Ollama")
                self.available_models = []
        except Exception as e:
            logger.warning(f"Could not connect to Ollama at {self.config.ollama_endpoint or 'default'}: {e}")
            logger.warning("AI explanations will be unavailable. Make sure Ollama is running.")
            logger.warning(f"Hint: Start Ollama with 'ollama serve' or check {self.config.ollama_endpoint}")
            self.client = None
            self.available_models = []
    
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
            system_prompt = (
                "You are a cybersecurity analyst explaining network security threats to IT administrators. "
                "Your explanations should be clear, accurate, and actionable. Follow these guidelines:\n"
                "1. Explain WHAT happened (the attack or suspicious activity)\n"
                "2. Explain WHY it matters (the potential impact or risk)\n"
                "3. Suggest WHAT TO DO (immediate response or investigation steps)\n"
                "4. If geographic context is provided, mention the location and any relevance (e.g., known threat actors from that region)\n"
                "5. Keep the explanation to 2-4 sentences, be direct and avoid speculation\n"
                "6. Use specific technical terms when accurate, but explain them briefly\n"
                "7. Focus on the immediate threat, not general security advice\n"
                "8. Do not repeat the prompt or add any preamble - start directly with the explanation"
            )
            user_prompt = self._build_prompt(threat)
            
            # Check if client is available
            if not self.client:
                logger.warning("Ollama client not available, using fallback explanation")
                return self._fallback_explanation(threat)
            
            # Call Ollama with system and user prompts
            response = self.client.generate(
                model=self.config.ollama_model,
                system=system_prompt,
                prompt=user_prompt,
                options={
                    'temperature': 0.4,  # Balanced temperature for accuracy with some creativity
                    'num_predict': 200,  # Allow slightly longer explanations for complex threats
                }
            )
            
            # Handle both dict and object responses
            if isinstance(response, dict):
                explanation = response.get('response', '').strip()
            elif hasattr(response, 'response'):
                explanation = response.response.strip()
            else:
                explanation = str(response).strip()
            
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
        """Build detailed prompt for Ollama with all available context."""
        # Start with severity and event type
        prompt_parts = [
            f"Threat detected: {threat.severity} severity {threat.event_type}",
            f"Description: {threat.description}"
        ]
        
        # Add source information
        if threat.source_ip:
            source_info = f"Source IP: {threat.source_ip}"
            
            # Add geographic context if available
            if threat.metadata and "geo_context" in threat.metadata:
                geo = threat.metadata["geo_context"]
                location = geo.get("location", "")
                isp = geo.get("isp", "")
                org = geo.get("org", "")
                as_num = geo.get("as_number", "")
                
                geo_details = []
                if location:
                    geo_details.append(location)
                if org and org != isp:
                    geo_details.append(f"Org: {org}")
                if isp and isp != "Unknown":
                    geo_details.append(f"ISP: {isp}")
                if as_num:
                    geo_details.append(as_num)
                
                if geo_details:
                    source_info += f" ({', '.join(geo_details)})"
            
            prompt_parts.append(source_info)
        
        # Add destination information
        if threat.dest_ip and threat.dest_ip != threat.source_ip:
            prompt_parts.append(f"Destination IP: {threat.dest_ip}")
        if threat.dest_port:
            prompt_parts.append(f"Destination Port: {threat.dest_port}")
        
        # Add timestamp context if recent
        if threat.timestamp:
            prompt_parts.append(f"Time: {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        # Combine all parts
        context = "\n".join(prompt_parts)
        
        # Build final prompt with clear instructions
        prompt = (
            f"{context}\n\n"
            f"Analyze this security threat and provide a clear explanation covering:\n"
            f"1. What type of attack or suspicious activity this is\n"
            f"2. Why it's a {threat.severity} severity concern and potential impact\n"
            f"3. Recommended immediate actions for the security team\n"
            f"Keep your response focused, professional, and 2-4 sentences."
        )
        
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
            # Build enhanced prompt for AI
            system_prompt = (
                "You are a Suricata IDS rule expert. Your task is to generate a valid Suricata drop rule.\n"
                "Rules must follow this exact syntax:\n"
                "drop ip [source_ip] any -> any any (msg:\"[clear reason]\"; sid:[unique_id]; rev:1;)\n\n"
                "Guidelines:\n"
                "- Use 'drop ip' action to block all traffic from the source\n"
                "- The msg field should clearly explain WHY this IP is being blocked (e.g., 'SSH brute force from Russia')\n"
                "- Use SID in the 9000000-9999999 range (custom rules)\n"
                "- Keep the msg concise but informative\n"
                "- Output ONLY the rule line, no explanations or additional text"
            )
            
            # Build detailed threat context
            context_parts = [
                f"Severity: {threat.severity}",
                f"Event Type: {threat.event_type}",
                f"Description: {threat.description}",
            ]
            
            if threat.source_ip:
                source_desc = f"Source IP: {threat.source_ip}"
                # Add geographic context to help with msg field
                if threat.metadata and "geo_context" in threat.metadata:
                    geo = threat.metadata["geo_context"]
                    location = geo.get("location", "")
                    isp = geo.get("isp", "")
                    if location:
                        source_desc += f" (Location: {location})"
                    if isp and isp != "Unknown":
                        source_desc += f" (ISP: {isp})"
                context_parts.append(source_desc)
            
            if threat.dest_port:
                context_parts.append(f"Target Port: {threat.dest_port}")
            
            user_prompt = (
                f"Generate a Suricata drop rule for this threat:\n\n"
                f"{chr(10).join(context_parts)}\n\n"
                f"Create a drop rule to block all traffic from {threat.source_ip or 'the source IP'}. "
                f"The msg field should reference the attack type and location if known. "
                f"Output only the complete Suricata rule."
            )
            
            # Check if client is available
            if not self.client:
                logger.warning("Ollama client not available, using fallback rule")
                return self._fallback_suricata_rule(threat)
            
            # Call Ollama
            response = self.client.generate(
                model=self.config.ollama_model,
                system=system_prompt,
                prompt=user_prompt,
                options={
                    'temperature': 0.2,  # Low temperature for consistent output
                    'num_predict': 100,  # Limit response length
                }
            )
            
            # Handle both dict and object responses
            if isinstance(response, dict):
                rule = response.get('response', '').strip()
            elif hasattr(response, 'response'):
                rule = response.response.strip()
            else:
                rule = str(response).strip()
            
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

