"""
Password Policy and Validation Module
Student ID: [SECURE_DATING_AUTH_2024]

Implements comprehensive password validation:
- Complexity requirements
- Common password checks
- Password strength estimation
"""

import re
from typing import Tuple, List
from .config import config


# Top 100 most common passwords (subset for demo - use larger list in production)
COMMON_PASSWORDS = {
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 
    '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
    'master', 'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow',
    '123123', '654321', 'superman', 'qazwsx', 'michael', 'football',
    'welcome', 'jesus', 'ninja', 'mustang', 'password1', '123456789',
    'adobe123', 'admin', 'letmein', '12345', 'master123'
}


class PasswordValidator:
    """
    Password validation against security policy.
    
    Enforces:
    - Minimum length
    - Character complexity (uppercase, lowercase, digits, special)
    - Common password checks
    - Breach database checks (placeholder)
    """
    
    def __init__(self):
        self.min_length = config.PASSWORD_MIN_LENGTH
        self.require_uppercase = config.PASSWORD_REQUIRE_UPPERCASE
        self.require_lowercase = config.PASSWORD_REQUIRE_LOWERCASE
        self.require_digits = config.PASSWORD_REQUIRE_DIGITS
        self.require_special = config.PASSWORD_REQUIRE_SPECIAL
        self.special_chars = config.PASSWORD_SPECIAL_CHARS
    
    def validate(self, password: str, user_data: dict = None) -> Tuple[bool, List[str]]:
        """
        Validate password against all policies.
        
        Args:
            password: Password to validate
            user_data: Optional dict with user email, name for context checks
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check minimum length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        # Check uppercase requirement
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check lowercase requirement
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check digit requirement
        if self.require_digits and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        # Check special character requirement
        if self.require_special:
            special_pattern = f'[{re.escape(self.special_chars)}]'
            if not re.search(special_pattern, password):
                errors.append(f"Password must contain at least one special character from: {self.special_chars}")
        
        # Check against common passwords
        if config.CHECK_COMMON_PASSWORDS:
            if password.lower() in COMMON_PASSWORDS:
                errors.append("Password is too common. Please choose a more unique password")
        
        # Check for user data in password (prevent using email/name)
        if user_data:
            if self._contains_user_data(password, user_data):
                errors.append("Password should not contain your email, name, or other personal information")
        
        # Check for sequential characters (123, abc, etc.)
        if self._has_sequential_chars(password):
            errors.append("Password should not contain sequential characters (e.g., '123', 'abc')")
        
        # Check for repeated characters (aaa, 111, etc.)
        if self._has_repeated_chars(password):
            errors.append("Password should not contain too many repeated characters")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def _contains_user_data(self, password: str, user_data: dict) -> bool:
        """Check if password contains user's personal information"""
        password_lower = password.lower()
        
        # Check email
        if 'email' in user_data:
            email = user_data['email'].lower()
            email_parts = email.split('@')[0].split('.')
            for part in email_parts:
                if len(part) >= 3 and part in password_lower:
                    return True
        
        # Check name
        if 'name' in user_data:
            name_parts = user_data['name'].lower().split()
            for part in name_parts:
                if len(part) >= 3 and part in password_lower:
                    return True
        
        return False
    
    def _has_sequential_chars(self, password: str, threshold: int = 3) -> bool:
        """Detect sequential characters (123, abc, etc.)"""
        password_lower = password.lower()
        
        for i in range(len(password_lower) - threshold + 1):
            substring = password_lower[i:i+threshold]
            
            # Check numeric sequences
            if substring.isdigit():
                if self._is_sequential_numeric(substring):
                    return True
            
            # Check alphabetic sequences
            if substring.isalpha():
                if self._is_sequential_alpha(substring):
                    return True
        
        return False
    
    def _is_sequential_numeric(self, s: str) -> bool:
        """Check if numeric string is sequential (123 or 321)"""
        if not s.isdigit():
            return False
        
        # Ascending
        ascending = all(int(s[i]) == int(s[i-1]) + 1 for i in range(1, len(s)))
        # Descending
        descending = all(int(s[i]) == int(s[i-1]) - 1 for i in range(1, len(s)))
        
        return ascending or descending
    
    def _is_sequential_alpha(self, s: str) -> bool:
        """Check if alphabetic string is sequential (abc or zyx)"""
        if not s.isalpha():
            return False
        
        # Ascending
        ascending = all(ord(s[i]) == ord(s[i-1]) + 1 for i in range(1, len(s)))
        # Descending
        descending = all(ord(s[i]) == ord(s[i-1]) - 1 for i in range(1, len(s)))
        
        return ascending or descending
    
    def _has_repeated_chars(self, password: str, threshold: int = 3) -> bool:
        """Detect repeated characters (aaa, 111, etc.)"""
        for i in range(len(password) - threshold + 1):
            substring = password[i:i+threshold]
            if len(set(substring)) == 1:  # All characters are the same
                return True
        return False
    
    def estimate_strength(self, password: str) -> Tuple[str, int]:
        """
        Estimate password strength.
        
        Returns:
            Tuple of (strength_label, score_out_of_100)
        """
        score = 0
        
        # Length scoring
        length = len(password)
        if length >= 12:
            score += 20
        elif length >= 10:
            score += 15
        elif length >= 8:
            score += 10
        else:
            score += 5
        
        # Character variety scoring
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_special = bool(re.search(f'[{re.escape(self.special_chars)}]', password))
        
        variety_score = sum([has_lowercase, has_uppercase, has_digits, has_special]) * 10
        score += variety_score
        
        # Bonus for mixing different character types
        char_types = sum([has_lowercase, has_uppercase, has_digits, has_special])
        if char_types >= 4:
            score += 20
        elif char_types >= 3:
            score += 10
        
        # Penalty for common passwords
        if password.lower() in COMMON_PASSWORDS:
            score -= 30
        
        # Penalty for sequential/repeated characters
        if self._has_sequential_chars(password):
            score -= 10
        if self._has_repeated_chars(password):
            score -= 10
        
        # Bonus for length beyond minimum
        if length > 15:
            score += min((length - 15) * 2, 20)
        
        # Ensure score is between 0-100
        score = max(0, min(100, score))
        
        # Determine strength label
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return strength, score
    
    def check_breach_database(self, password: str) -> bool:
        """
        Check if password appears in known breach databases.
        
        PLACEHOLDER: In production, integrate with:
        - Have I Been Pwned API (k-anonymity model)
        - Internal breach database
        
        Returns:
            True if password is compromised
        """
        # TODO: Implement actual breach database check
        # Example using haveibeenpwned API:
        # 1. Hash password with SHA-1
        # 2. Send first 5 chars of hash to API (k-anonymity)
        # 3. Check if full hash appears in response
        
        # For demo, just check against common passwords
        return password.lower() in COMMON_PASSWORDS


# Global validator instance
password_validator = PasswordValidator()


def validate_password(password: str, user_data: dict = None) -> Tuple[bool, List[str]]:
    """
    Convenience function for password validation.
    
    Args:
        password: Password to validate
        user_data: Optional dict with user info
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    return password_validator.validate(password, user_data)


def get_password_strength(password: str) -> Tuple[str, int]:
    """
    Convenience function for password strength estimation.
    
    Returns:
        Tuple of (strength_label, score_out_of_100)
    """
    return password_validator.estimate_strength(password)