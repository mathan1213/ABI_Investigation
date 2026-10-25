import {
  splitAndCleanPhoneNumber,
  validateNationalPhone,
  maskE164Phone,
} from './phoneUtils';

function assert(condition: boolean, msg: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${msg}`);
  }
}

export function runPhoneTests(): boolean {
  // 1. Country code auto-detection from pasted +91 number
  const test1 = splitAndCleanPhoneNumber('+916379617482', '+1');
  assert(test1.countryCode === '+91', 'test1 countryCode');
  assert(test1.nationalNumber === '6379617482', 'test1 nationalNumber');

  // 2. Country code auto-detection from pasted number without plus (e.g. 916379617482)
  const test2 = splitAndCleanPhoneNumber('916379617482', '+1');
  assert(test2.countryCode === '+91', 'test2 countryCode');
  assert(test2.nationalNumber === '6379617482', 'test2 nationalNumber');

  // 3. Leading zero stripping (e.g. 09876543210)
  const test3 = splitAndCleanPhoneNumber('09876543210', '+91');
  assert(test3.countryCode === '+91', 'test3 countryCode');
  assert(test3.nationalNumber === '9876543210', 'test3 nationalNumber');

  // 4. Formatting stripping (spaces, dashes, parentheses)
  const test4 = splitAndCleanPhoneNumber('+91 (637) 961-7482', '+91');
  assert(test4.countryCode === '+91', 'test4 countryCode');
  assert(test4.nationalNumber === '6379617482', 'test4 nationalNumber');

  // 5. US number auto-detection
  const test5 = splitAndCleanPhoneNumber('+1 (415) 555-2671', '+91');
  assert(test5.countryCode === '+1', 'test5 countryCode');
  assert(test5.nationalNumber === '4155552671', 'test5 nationalNumber');

  // 6. India validation: exactly 10 digits starting with 6, 7, 8, 9
  assert(validateNationalPhone('+91', '6379617482').isValid, 'India valid 6');
  assert(validateNationalPhone('+91', '7379617482').isValid, 'India valid 7');
  assert(validateNationalPhone('+91', '8379617482').isValid, 'India valid 8');
  assert(validateNationalPhone('+91', '9379617482').isValid, 'India valid 9');

  // India validation: starting with 5 (invalid)
  assert(!validateNationalPhone('+91', '5379617482').isValid, 'India invalid 5');
  // India validation: 9 digits (too short)
  assert(!validateNationalPhone('+91', '987654321').isValid, 'India 9 digits');
  // India validation: 11 digits (too long)
  assert(!validateNationalPhone('+91', '98765432100').isValid, 'India 11 digits');

  // 7. Non-India validation: 6 to 14 digits
  assert(validateNationalPhone('+1', '4155552671').isValid, 'US valid');
  assert(validateNationalPhone('+44', '7911123456').isValid, 'UK valid');
  assert(!validateNationalPhone('+1', '12345').isValid, 'US < 6');
  assert(!validateNationalPhone('+1', '123456789012345').isValid, 'US > 14');

  // 8. Masking: +91*****7482
  assert(maskE164Phone('+91', '6379617482') === '+91*****7482', 'mask +91');
  assert(maskE164Phone('+1', '4155552671') === '+1*****2671', 'mask +1');

  return true;
}
