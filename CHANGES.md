# CHANGELOG

## v2.0.1

- Update gemspec description, no longer maintained.

## v2.0.0

- Use RbNaCl for SHA-512 hash and HMAC SHA-256. Backward incompatible change with previous use of SHA-256.
- Refactored to eliminate use of OpenSSL::BN in favor of Ruby Bignum. Its better documented and the code is more intentional. As of [Ruby 2.1](http://globaldev.co.uk/2014/05/ruby-2-1-in-detail/) Bignum uses the GNU Multiple Precision Arithmetic Library (GMP) to improve performance.
- New internal prime number generation using Miller-Rabin primality tests which eliminates previous OpenSSL::BN#generate_prime bugs.
- Use RbNaCl to generate random numbers.
- Change the list of supported Ruby VMs to match RbNaCl.
- Use backports gem to support Bignum#bit_length which was introduced in Ruby 2.1
- Fixed all Rubocop warnings.
- 100% code test coverage as measured with COCO.
- Use RbNaCl secure constant-time comparison for comparing secret objects to one another.
- Added additional tests for utility functions.

## v1.0.0

- Version 1.0.0 is an almost complete rewrite of the original code.
   This version is NOT backwards compatible with the shares generated
   with previous version. The API for this version is significantly
   changed as well. You will need to make some (hopefully simple)
   code changes to use this newer version. See the README.md file
   for details.

## v0.3

- Added support for setting your own secret using the set_fixed_secret() method.

## v0.2

- Bugfix in Langrange interpolation, which broke 2/2 sharing.
- Added secret_password method to represent the secret in Base64.

## v0.1

- Initial version
