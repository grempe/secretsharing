# -*- encoding: utf-8 -*-

# Copyright 2011-2013 Glenn Rempe

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
    # Creates a random number of a certain bitlength, optionally ensuring
    # the bitlength by setting the highest bit to 1.
    def get_random_number(bitlength)
      byte_length = (bitlength / 8.0).ceil
      rand_hex    = OpenSSL::Random.random_bytes(byte_length).each_byte.to_a.map { |a| sprintf('%02x', a) }.join('')
      rand        = OpenSSL::BN.new(rand_hex, 16)

      begin
        rand.mask_bits!(bitlength)
      rescue OpenSSL::BNError
        # never mind if there was an error, this just means
        # rand was already smaller than 2^bitlength - 1
      end

      rand.set_bit!(bitlength)
      rand
    end

    # Computes the smallest prime of a given bitlength. Uses prime_fasttest
    # from the OpenSSL library with 20 attempts to be compatible to openssl
    # prime, which is used in the OpenXPKI::Crypto::Secret::Split library.
    def smallest_prime_of_bitlength(bitlength)
      # start with 2^bit_length + 1
      test_prime = OpenSSL::BN.new((2**bitlength + 1).to_s)
      prime_found = false

      until prime_found
        # prime_fasttest? 20 do be compatible to
        # openssl prime, which is used in
        # OpenXPKI::Crypto::Secret::Split
        prime_found = test_prime.prime_fasttest?(20)
        test_prime += 2
      end

      test_prime
    end

    # Backported for Ruby 1.8.7, REE, JRuby, Rubinious
    def urlsafe_decode64(str)
      return Base64.urlsafe_decode64(str) if Base64.respond_to?(:urlsafe_decode64)

      if str.include?('\n')
        fail(ArgumentError, 'invalid base64')
      else
        Base64.decode64(str)
      end
    end

    # Backported for Ruby 1.8.7, REE, JRuby, Rubinious
    def urlsafe_encode64(bin)
      return Base64.urlsafe_encode64(bin) if Base64.respond_to?(:urlsafe_encode64)
      Base64.encode64(bin).tr("\n", '')
    end
  end # module Shamir
end # module SecretSharing
