# -*- encoding: utf-8 -*-

# Copyright 2011-2015 Glenn Rempe

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module SecretSharing
  # Module for common methods shared across Container, Secret, or Share
  module Shamir

    # Create a random number of a specified Byte length
    # returns Bignum
    def get_random_number(bytes)
      RbNaCl::Util.bin2hex(RbNaCl::Random.random_bytes(bytes).to_s).to_i(16)
    end

    # Creates a random number of a exact bitlength
    # returns Bignum
    def get_random_number_with_bitlength(bits)
      byte_length = (bits / 8.0).ceil + 5
      random_num = get_random_number(byte_length)

      # Convert to binary String of 1's and 0's
      random_num_bin_str = random_num.to_s(2)

      # Concatenate additional random binary String values
      # until we have enought bits. Get five Bytes at a time.
      while random_num_bin_str.length < bits
        random_num_bin_str += get_random_number(5).to_s(2)
      end

      # Return only the exact specified number of bits as a Numeric (Bignum)
      random_num_bin_str.slice(0, bits).to_i(2)
    end

    # Supports #miller_rabin_prime?
    def mod_exp(n, e, mod)
      fail ArgumentError, 'negative exponent' if e < 0
      prod = 1
      base = n % mod

      until e.zero?
        prod = (prod * base) % mod if e.odd?
        e >>= 1
        base = (base * base) % mod
      end

      prod
    end

    # An implementation of the miller-rabin primality test.
    # See : http://primes.utm.edu/prove/merged.html
    # See : http://rosettacode.org/wiki/Miller-Rabin_primality_test#Ruby
    # See : https://crypto.stackexchange.com/questions/71/how-can-i-generate-large-prime-numbers-for-rsa
    # See : https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    #
    # Pseudocode:
    # ###########
    # Input: n > 3, an odd integer to be tested for primality;
    # Input: k, a parameter that determines the accuracy of the test
    # Output: composite if n is composite, otherwise probably prime
    # write n − 1 as 2s·d with d odd by factoring powers of 2 from n − 1
    # WitnessLoop: repeat k times:
    #    pick a random integer a in the range [2, n − 2]
    #    x ← ad mod n
    #    if x = 1 or x = n − 1 then do next WitnessLoop
    #    repeat s − 1 times:
    #       x ← x2 mod n
    #       if x = 1 then return composite
    #       if x = n − 1 then do next WitnessLoop
    #    return composite
    # return probably prime
    #
    # Example : p primes = (3..1000).step(2).find_all {|i| miller_rabin_prime?(i,10)}
    def miller_rabin_prime?(n, g = 1000)
      return false if n == 1
      return true if n == 2

      d = n - 1
      s = 0

      while d % 2 == 0
        d /= 2
        s += 1
      end

      g.times do
        a = 2 + rand(n - 4)
        x = mod_exp(a, d, n) # x = (a**d) % n
        next if x == 1 || x == n - 1
        for r in (1..s - 1)
          x = mod_exp(x, 2, n) # x = (x**2) % n
          return false if x == 1
          break if x == n - 1
        end
        return false if x != n - 1
      end

      true # probably
    end

    # See : http://planetmath.org/SafePrime
    # See : https://en.wikipedia.org/wiki/Safe_prime
    def safe_prime?(prime)
      miller_rabin_prime?((prime - 1)/2)
    end

    # Finds a random prime number of *at least* bitlength
    # Validate primeness using the miller-rabin primality test.
    # Increment through odd numbers to test candidates until one is found.
    # Generates 'safe' primes by default.
    def get_prime_number(bitlength, safe = true)
      prime_cand = get_random_number_with_bitlength(bitlength + 1)
      prime_cand += 1 if prime_cand.even?

      while !miller_rabin_prime?(prime_cand)
        # keep it odd
        prime_cand += 2

        # must guarantee that returned primes are of *at least* bitlengh + 1
        if prime_cand.bit_length < bitlength + 1
          next
        end

        # only safe primes allowed by default
        if safe && !safe_prime?(prime_cand)
          next
        end
      end

      prime_cand
    end

    # FIXME : Needs focused tests

    # Evaluate the polynomial at x.
    def evaluate_polynomial_at(x, coefficients, prime)
      result = 0

      coefficients.each_with_index do |c, i|
        result += c * (x**i)
        result %= prime
      end

      result
    end

    # FIXME : Needs focused tests

    # Part of the Lagrange interpolation.
    # This is l_j(0), i.e.
    # \prod_{x_j \neq x_i} \frac{-x_i}{x_j - x_i}
    # for more information compare Wikipedia:
    # http://en.wikipedia.org/wiki/Lagrange_form
    def lagrange(x, shares)
      prime        = shares.first.prime
      other_shares = shares.reject { |s| s.x == x }

      results = other_shares.map do |s|
        minus_xi = OpenSSL::BN.new("#{-s.x}")
        one_over_xj_minus_xi = OpenSSL::BN.new("#{x - s.x}").mod_inverse(prime)
        minus_xi.mod_mul(one_over_xj_minus_xi, prime)
      end

      results.reduce { |a, e| a.mod_mul(e, prime) }
    end

    # Backported for Ruby 1.8.7, REE, JRuby, Rubinious
    def usafe_decode64(str)
      str = str.strip
      return Base64.urlsafe_decode64(str) if Base64.respond_to?(:urlsafe_decode64)

      if str.include?('\n')
        fail(ArgumentError, 'invalid base64')
      else
        Base64.decode64(str)
      end
    end

    # Backported for Ruby 1.8.7, REE, JRuby, Rubinious
    def usafe_encode64(bin)
      bin = bin.strip
      return Base64.urlsafe_encode64(bin) if Base64.respond_to?(:urlsafe_encode64)
      Base64.encode64(bin).tr("\n", '')
    end
  end # module Shamir
end # module SecretSharing
