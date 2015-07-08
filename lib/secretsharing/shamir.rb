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
      byte_length = (bits / 8.0).ceil + 10
      random_num = get_random_number(byte_length)
      random_num_bin_str = random_num.to_s(2) # Get 1's and 0's

      # Slice off only the bits we require, convert Bits to Numeric (Bignum)
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
    # Example : p primes = (3..1000).step(2).find_all {|i| miller_rabin_prime?(i,10)}
    def miller_rabin_prime?(n, g = 1000)
      return false if n == 1
      return true if n == 2

      d = n - 1
      s = 0

      while d.even?
        d /= 2
        s += 1
      end

      g.times do
        a = 2 + rand(n - 4)
        x = mod_exp(a, d, n) # x = (a**d) % n
        next if x == 1 || x == n - 1
        (1..s - 1).each do
          x = mod_exp(x, 2, n) # x = (x**2) % n
          return false if x == 1
          break if x == n - 1
        end
        return false if x != n - 1
      end

      true # probably
    end

    # Finds a random prime number of *at least* bitlength
    # Validate primeness using the miller-rabin primality test.
    # Increment through odd numbers to test candidates until a good prime is found.
    def get_prime_number(bitlength)
      prime_cand = get_random_number_with_bitlength(bitlength + 1)
      prime_cand += 1 if prime_cand.even?

      # loop, adding 2 to keep it odd, until prime_cand is prime.
      (prime_cand += 2) until miller_rabin_prime?(prime_cand)

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

    def extended_gcd(a, b)
      last_remainder = a.abs
      remainder      = b.abs
      x              = 0
      last_x         = 1
      y              = 1
      last_y         = 0

      until remainder.zero?
        # rubocop:disable Style/ParallelAssignment
        last_remainder, (quotient, remainder) = remainder, last_remainder.divmod(remainder)
        x, last_x = last_x - quotient * x, x
        y, last_y = last_y - quotient * y, y
        # rubocop:enable Style/ParallelAssignment
      end

      [last_remainder, last_x * (a < 0 ? -1 : 1)]
    end

    # Calculate the Modular Inverse.
    # See : http://rosettacode.org/wiki/Modular_inverse#Ruby
    # Based on pseudo code from http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Iterative_method_2
    def invmod(e, et)
      g, x = extended_gcd(e, et)
      fail ArgumentError, 'Teh maths are broken!' if g != 1
      x % et
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
        minus_xi = -s.x
        # was OpenSSL::BN#mod_inverse
        one_over_xj_minus_xi = invmod(x - s.x, prime)
        # was OpenSSL::BN#mod_mul : (self * other) % m
        (minus_xi * one_over_xj_minus_xi) % prime
      end

      results.reduce { |a, e| (a * e) % prime }
    end
  end # module Shamir
end # module SecretSharing
