# -*- encoding: utf-8 -*-

# Copyright 2011-2013 Alexander Klink and Glenn Rempe

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'openssl'
require 'digest/sha1'
require 'base64'

module SecretSharing
  module Shamir
    # The SecretSharing::Shamir::Container class can be used to share random
    # secrets between n people, so that k < n people can recover the
    # secret, but k-1 people learn nothing (in an information-theoretical
    # sense) about the secret.
    #
    # For a theoretical background, see:
    #   http://www.cs.tau.ac.il/~bchor/Shamir.html
    #   http://en.wikipedia.org/wiki/Secret_sharing#Shamir.27s_scheme
    #
    # To share a secret, create a new SecretSharing::Shamir::Container object and
    # then call the create_random_secret() method. The secret is now in
    # the secret attribute and the shares are an array in the shares attribute.
    #
    # Alternatively, you can call the set_fixed_secret() method with an
    # OpenSSL::BN object (or something that can be passed to OpenSSL::BN.new)
    # to set your own secret.
    #
    # To recover a secret, create another SecretSharing::Shamir::Container object and
    # add the necessary shares to it using the '<<' method. Once enough
    # shares have been added, the secret can be recovered in the secret
    # attribute.
    #
    class Container
      attr_reader :n, :k, :secret, :secret_bitlength, :shares

      MIN_SECRET_BITLENGTH     = 1
      DEFAULT_SECRET_BITLENGTH = 256
      MAX_SECRET_BITLENGTH     = 4096

      MIN_SHARES               = 2
      MAX_SHARES               = 512

      # To create a new SecretSharing::Shamir::Container object, you can
      # pass either just n, or n and k where:
      #
      #   n = The total number of shares that will be created.
      #   k = The threshold number of the total shares needed to
      #       recreate the original secret. (Default = n)
      #
      # For example:
      #
      #   # 3(k) out of 5(n) shares needed to recover secret
      #   s = SecretSharing::Shamir::Container.new(5, 3)
      #
      #   # 3(k) out of 3(n) shares needed to recover secret
      #   s = SecretSharing::Shamir::Container.new(3)
      #
      def initialize(n, k = n)
        @n               = n.to_i
        @k               = k.to_i

        fail ArgumentError, 'n must be an Integer' unless @n.is_a?(Integer)
        fail ArgumentError, 'k must be an Integer' unless @k.is_a?(Integer)

        fail ArgumentError, 'k must be <= n'              unless @k <= @n
        fail ArgumentError, 'k must be >= #{MIN_SHARES}'  unless @k >= MIN_SHARES
        fail ArgumentError, 'n must be <= #{MAX_SHARES}'  unless @n <= MAX_SHARES

        @secret          = nil
        @shares          = []
        @received_shares = []
      end

      # Check whether the secret is set.
      def secret_set?
        !@secret.nil?
      end

      # Create a random secret of a certain bitlength. Returns the
      # secret and stores it in the 'secret' attribute.
      def create_random_secret(bitlength = DEFAULT_SECRET_BITLENGTH)
        fail 'a secret has already been set' if secret_set?
        fail ArgumentError, "min bitlength is #{MIN_SECRET_BITLENGTH}" if bitlength < MIN_SECRET_BITLENGTH
        fail ArgumentError, "max bitlength is #{MAX_SECRET_BITLENGTH}" if bitlength > MAX_SECRET_BITLENGTH

        @secret = get_random_number(bitlength)
        @secret_bitlength = bitlength
        create_shares
        @secret
      end

      # Set the secret to a fixed OpenSSL::BN value. Stores it
      # in the 'secret' attribute, creates the corresponding shares and
      # returns the secret
      def set_fixed_secret(secret)
        fail 'a secret has already been set' if secret_set?

        secret = OpenSSL::BN.new(secret) unless secret.is_a?(OpenSSL::BN)
        fail "the bitlength of the fixed secret provided is #{secret.num_bits}, the min bitlength allowed is #{MIN_SECRET_BITLENGTH}" if secret.num_bits < MIN_SECRET_BITLENGTH
        fail "the bitlength of the fixed secret provided is #{secret.num_bits}, the max bitlength allowed is #{MAX_SECRET_BITLENGTH}" if secret.num_bits > MAX_SECRET_BITLENGTH

        @secret = secret
        @secret_bitlength = secret.num_bits
        create_shares
        @secret
      end

      # The secret in a password representation (Base64-encoded)
      def secret_password
        fail 'Secret not (yet) set.' unless secret_set?
        Base64.encode64([@secret.to_s(16)].pack('h*')).split("\n").join
      end

      # Add a secret share to the object. Accepts either a
      # SecretSharing::Shamir::Share instance or a String representing one.
      # Returns secret as a String if enough valid shares have been added
      # to recover the secret, and false otherwise. The secret can also be recovered
      # later with SecretSharing::Shamir::Container#secret if enough valid shares were previously
      # provided.
      def <<(share)
        # You can't add more shares than were originally generated with value of @n
        fail ArgumentError, 'You have added more shares than allowed by the value of @n' if @received_shares.size >= @n

        share = SecretSharing::Shamir::Share.new(share) unless share.is_a?(SecretSharing::Shamir::Share)
        @received_shares << share unless @received_shares.include?(share)
        recover_secret
      end

      # Computes the smallest prime of a given bitlength. Uses prime_fasttest
      # from the OpenSSL library with 20 attempts to be compatible to openssl
      # prime, which is used in the OpenXPKI::Crypto::Secret::Split library.
      def self.smallest_prime_of_bitlength(bitlength)
        # start with 2^bit_length + 1
        test_prime = OpenSSL::BN.new((2**bitlength + 1).to_s)
        prime_found = false

        until prime_found
          # prime_fasttest? 20 do be compatible to
          # openssl prime, which is used in
          # OpenXPKI::Crypto::Secret::Split
          prime_found = test_prime.prime_fasttest? 20
          test_prime += 2
        end

        test_prime
      end

      private

        # Creates a random number of a certain bitlength, optionally ensuring
        # the bitlength by setting the highest bit to 1.
        def get_random_number(bitlength, highest_bit_one = true)
          byte_length = (bitlength / 8.0).ceil
          rand_hex    = OpenSSL::Random.random_bytes(byte_length).each_byte.to_a.map { |a| sprintf('%02x', a) }.join('')
          rand        = OpenSSL::BN.new(rand_hex, 16)

          begin
            rand.mask_bits!(bitlength)
          rescue OpenSSL::BNError
            # never mind if there was an error, this just means
            # rand was already smaller than 2^bitlength - 1
          end

          rand.set_bit!(bitlength) if highest_bit_one
          rand
        end

        # Creates the shares by computing random coefficients for a polynomial
        # and then computing points on this polynomial.
        def create_shares
          @coefficients = []
          @coefficients[0] = @secret

          # round up to next nibble
          next_nibble_bitlength = @secret_bitlength + (4 - (@secret_bitlength % 4))
          prime_bitlength       = next_nibble_bitlength + 1
          @prime                = self.class.smallest_prime_of_bitlength(prime_bitlength)

          # compute random coefficients
          (1..k - 1).each { |x| @coefficients[x] = get_random_number(@secret_bitlength) }

          (1..n).each { |x| @shares[x - 1] = construct_share(x, prime_bitlength) }
        end

        # Construct a share by evaluating the polynomial at x and creating
        # a SecretSharing::Shamir::Share object.
        def construct_share(x, bitlength)
          p_x = evaluate_polynomial_at(x)
          SecretSharing::Shamir::Share.new(x, p_x, @prime, bitlength)
        end

        # Evaluate the polynomial at x.
        def evaluate_polynomial_at(x)
          result = OpenSSL::BN.new('0')

          @coefficients.each_with_index do |coeff, i|
            result += coeff * OpenSSL::BN.new(x.to_s)**i
            result %= @prime
          end

          result
        end

        # Recover the secret by doing Lagrange interpolation.
        def recover_secret
          return false unless @received_shares.length >= @k

          @secret = OpenSSL::BN.new('0')

          @received_shares.each do |share|
            l_x     = l(share.x, @received_shares)
            summand = share.y * l_x
            summand %= share.prime
            @secret += summand
            @secret %= share.prime
          end

          @secret
        end

        # Part of the Lagrange interpolation.
        # This is l_j(0), i.e.
        # \prod_{x_j \neq x_i} \frac{-x_i}{x_j - x_i}
        # for more information compare Wikipedia:
        # http://en.wikipedia.org/wiki/Lagrange_form
        def l(x, shares)
          result = shares.select { |s| s.x != x }

          result = result.map do |s|
            minus_xi = OpenSSL::BN.new((-s.x).to_s)
            one_over_xj_minus_xi = OpenSSL::BN.new((x - s.x).to_s).mod_inverse(shares[0].prime)
            minus_xi.mod_mul(one_over_xj_minus_xi, shares[0].prime)
          end

          (result.reduce { |a, e| a.mod_mul(e, shares[0].prime) })
        end
    end # class Container
  end # module Shamir
end # module SecretSharing
