export interface Country {
  code: string;       // E.g. '+91'
  dialCode: string;   // E.g. '91'
  name: string;       // E.g. 'India'
  flag: string;       // E.g. '🇮🇳'
}

export const COUNTRIES: Country[] = [
  { code: '+91', dialCode: '91', name: 'India', flag: '🇮🇳' },
  { code: '+1', dialCode: '1', name: 'USA / Canada', flag: '🇺🇸' },
  { code: '+44', dialCode: '44', name: 'United Kingdom', flag: '🇬🇧' },
  { code: '+971', dialCode: '971', name: 'UAE', flag: '🇦🇪' },
  { code: '+49', dialCode: '49', name: 'Germany', flag: '🇩🇪' },
  { code: '+33', dialCode: '33', name: 'France', flag: '🇫🇷' },
  { code: '+61', dialCode: '61', name: 'Australia', flag: '🇦🇺' },
  { code: '+65', dialCode: '65', name: 'Singapore', flag: '🇸🇬' },
  { code: '+81', dialCode: '81', name: 'Japan', flag: '🇯🇵' },
  { code: '+55', dialCode: '55', name: 'Brazil', flag: '🇧🇷' },
  { code: '+27', dialCode: '27', name: 'South Africa', flag: '🇿🇦' },
  { code: '+234', dialCode: '234', name: 'Nigeria', flag: '🇳🇬' },
];

/**
 * Splits and cleans a raw phone input.
 * Strips spaces, hyphens, parentheses, and leading 0.
 * Automatically recognizes country code if user pasted a full number (+91..., 91...).
 */
export function splitAndCleanPhoneNumber(
  rawInput: string,
  currentCountryCode: string
): { countryCode: string; nationalNumber: string } {
  let clean = rawInput.trim();
  if (!clean) {
    return { countryCode: currentCountryCode, nationalNumber: '' };
  }

  // Remove spaces, hyphens, parentheses
  clean = clean.replace(/[\s\-()]/g, '');

  // If pasted with leading '+'
  if (clean.startsWith('+')) {
    const withoutPlus = clean.slice(1);
    // Match against known country dial codes, longest prefix first
    const sorted = [...COUNTRIES].sort((a, b) => b.dialCode.length - a.dialCode.length);
    const matched = sorted.find((c) => withoutPlus.startsWith(c.dialCode));
    if (matched) {
      let national = withoutPlus.slice(matched.dialCode.length);
      if (national.startsWith('0')) national = national.slice(1);
      return { countryCode: matched.code, nationalNumber: national.replace(/\D/g, '') };
    }
  }

  // If pasted with international dial code without plus (e.g. 916379617482)
  const sorted = [...COUNTRIES].sort((a, b) => b.dialCode.length - a.dialCode.length);
  for (const c of sorted) {
    if (clean.startsWith(c.dialCode) && clean.length > c.dialCode.length + 5) {
      let national = clean.slice(c.dialCode.length);
      if (national.startsWith('0')) national = national.slice(1);
      return { countryCode: c.code, nationalNumber: national.replace(/\D/g, '') };
    }
  }

  // If national number has a leading 0 (e.g. 09876543210)
  if (clean.startsWith('0')) {
    clean = clean.slice(1);
  }

  // Retain only digits
  return {
    countryCode: currentCountryCode,
    nationalNumber: clean.replace(/\D/g, ''),
  };
}

/**
 * Validates national phone digits according to country rules.
 */
export function validateNationalPhone(
  countryCode: string,
  nationalNumber: string
): { isValid: boolean; message: string } {
  const digits = nationalNumber.replace(/\D/g, '');
  if (!digits) {
    return {
      isValid: false,
      message: countryCode === '+91'
        ? 'Enter a 10-digit Indian mobile number'
        : 'Enter your mobile number without leading 0',
    };
  }

  if (countryCode === '+91') {
    if (digits.length !== 10) {
      return {
        isValid: false,
        message: 'Enter a 10-digit Indian mobile number starting with 6, 7, 8 or 9',
      };
    }
    if (!/^[6-9]/.test(digits)) {
      return {
        isValid: false,
        message: 'Indian mobile numbers must start with 6, 7, 8 or 9',
      };
    }
    return {
      isValid: true,
      message: 'Valid 10-digit Indian mobile number ✓',
    };
  }

  // Non-India: accept 6 to 14 digits
  if (digits.length < 6 || digits.length > 14) {
    return {
      isValid: false,
      message: 'Enter a valid 6 to 14 digit mobile number',
    };
  }

  return {
    isValid: true,
    message: 'Valid phone number ✓',
  };
}

/**
 * Builds masked E.164 phone string (e.g. +91*****7482).
 */
export function maskE164Phone(countryCode: string, nationalNumber: string): string {
  const digits = nationalNumber.replace(/\D/g, '');
  if (digits.length <= 4) {
    return `${countryCode}*****${digits}`;
  }
  const last4 = digits.slice(-4);
  return `${countryCode}*****${last4}`;
}
