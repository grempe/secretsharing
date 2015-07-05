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

    # Creates a random prime number of *at least* bitlength
    def get_prime_number(bitlength)
      # FIXME : bignum problem : another way to generate large primes?
      # BN_generate_prime_ex() generates a pseudo-random prime number of ***at least*** bit length bits. If ret is not NULL, it will be used to store the number.
      # https://wiki.openssl.org/index.php/Manual:BN_generate_prime(3)

      # FIXME : Why does generate_prime always return 35879 for bitlength 1-15
      # OpenSSL::BN::generate_prime(1).to_i
      # => 35879
      # Do we need to make sure that prime_bitlength is not shorter than 64 bits?
      # See : https://www.mail-archive.com/openssl-dev@openssl.org/msg18835.html
      # See : http://ardoino.com/2005/11/maths-openssl-primes-random/
      # See : http://www.openssl.org/docs/apps/genrsa.html  "Therefore the number of bits should not be less that 64."

      OpenSSL::BN.generate_prime(bitlength)
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

    # FIXME : Needs focused tests

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

    # FIXME : Needs focused tests

    # Backported for Ruby 1.8.7, REE, JRuby, Rubinious
    def usafe_encode64(bin)
      bin = bin.strip
      return Base64.urlsafe_encode64(bin) if Base64.respond_to?(:urlsafe_encode64)
      Base64.encode64(bin).tr("\n", '')
    end
  end # module Shamir
end # module SecretSharing
