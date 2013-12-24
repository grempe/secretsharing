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
    class Container
      include SecretSharing::Shamir
      attr_reader :n, :k, :secret, :shares

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
      end

      def secret?
        @secret.is_a?(SecretSharing::Shamir::Secret)
      end

      def secret=(sec)
        fail ArgumentError, 'secret has already been set' if secret?
        fail ArgumentError, 'secret must be a SecretSharing::Shamir::Secret instance' unless sec.is_a?(SecretSharing::Shamir::Secret)
        @secret = sec
        create_shares
        true
      end

      # Add a secret share to the object. Accepts a
      # SecretSharing::Shamir::Share instance.
      # Returns secret as a SecretSharing::Shamir::Secret if enough valid shares have been added
      # to recover the secret, and false otherwise. The secret can also be recovered
      # later with SecretSharing::Shamir::Container#secret if enough valid shares were previously
      # provided.
      def <<(share)
        # You can't add more shares than were originally generated with value of @n
        fail ArgumentError, 'You have added more shares than allowed by the value of @n' if @shares.size >= @n

        share = SecretSharing::Shamir::Share.new(:share => share) unless share.is_a?(SecretSharing::Shamir::Share)
        @shares << share unless @shares.include?(share)
        recover_secret
      end

      private

        # Creates the shares by computing random coefficients for a polynomial
        # and then computing points on this polynomial.
        def create_shares
          @coefficients = []
          @coefficients[0] = @secret.secret

          # round up to next nibble
          next_nibble_bitlength = @secret.bitlength + (4 - (@secret.bitlength % 4))
          prime_bitlength       = next_nibble_bitlength + 1
          @prime                = smallest_prime_of_bitlength(prime_bitlength)

          # compute random coefficients
          (1..k - 1).each { |x| @coefficients[x] = get_random_number(@secret.bitlength) }

          (1..n).each { |x| @shares[x - 1] = construct_share(x, prime_bitlength) }
        end

        # Construct a share by evaluating the polynomial at x and creating
        # a SecretSharing::Shamir::Share object.
        def construct_share(x, bitlength)
          p_x = evaluate_polynomial_at(x)
          SecretSharing::Shamir::Share.new(:x => x, :y => p_x, :prime => @prime, :prime_bitlength => bitlength, :k => @k, :n => @n, :hmac => @secret.hmac)
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
          return false unless @shares.length >= @k

          # All Shares must have the same HMAC or they were derived from different Secrets
          hmacs = @shares.map { |s| s.hmac }.uniq
          fail ArgumentError, 'Share mismatch. Not all Shares have a common HMAC.' unless hmacs.size == 1

          @secret = SecretSharing::Shamir::Secret.new(:secret => OpenSSL::BN.new('0'))

          @shares.each do |share|
            l_x     = l(share.x, @shares)
            summand = share.y * l_x
            summand %= share.prime
            @secret.secret += summand
            @secret.secret %= share.prime
          end

          if @secret && @secret.is_a?(SecretSharing::Shamir::Secret) && @secret.valid_hmac?
            return @secret
          else
            fail ArgumentError, 'Secret recovery failure. The generated Secret does not match the HMACs in the Shares provided.'
          end
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
