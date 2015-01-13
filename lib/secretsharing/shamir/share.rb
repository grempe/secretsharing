# -*- encoding: utf-8 -*-

# Copyright 2011-2015 Alexander Klink and Glenn Rempe

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
    # A SecretSharing::Shamir::Share object represents a share in the
    # Shamir secret sharing scheme. The share consists of a point (x,y) on
    # a polynomial over Z/Zp, where p is a prime.
    class Share
      include SecretSharing::Shamir
      extend SecretSharing::Shamir
      attr_accessor :share, :version, :hmac, :k, :n, :x, :y, :prime, :prime_bitlength

      def initialize(opts = {})
        opts = {
          :share           => nil,
          :version         => 1,
          :hmac            => nil,
          :k               => nil,
          :n               => nil,
          :x               => nil,
          :y               => nil,
          :prime           => nil,
          :prime_bitlength => nil
        }.merge!(opts)

        opts.each_key do |k|
          if self.respond_to?("#{k}=")
            send("#{k}=", opts[k])
          else
            fail ArgumentError, "Argument '#{k}' is not allowed"
          end
        end

        # Decode and unpack a String share if provided
        unpack_share(@share) unless @share.nil?

        if @share.nil?
          errors = [:version, :hmac, :k, :n, :x, :y, :prime, :prime_bitlength].map { |e| e if send("#{e}").nil? }.compact
          fail ArgumentError, "#{errors.join(', ')} expected." unless errors.empty?
        end
      end

      def ==(other)
        other.to_s == to_s
      end

      # FIXME : Add an HMAC which 'signs' all of the attributes of the hash and which gets verified on re-hydration to make sure
      # that none of the attributes changed?

      def to_hash
        [:version, :hmac, :k, :n, :x, :y, :prime, :prime_bitlength].reduce({}) do |h, element|
          if [:hmac].include?(element)
            h.merge(element => send(element))
          else
            # everything else is an Integer/Bignum
            h.merge(element => send(element).to_i)
          end
        end
      end

      def to_json
        MultiJson.dump(to_hash)
      end

      def to_s
        usafe_encode64(to_json)
      end

      # Creates the shares by computing random coefficients for a polynomial
      # and then computing points on this polynomial.
      def self.create_shares(k, n, secret)
        shares                = []
        coefficients          = []
        coefficients[0]       = secret.secret

        # round up to next nibble
        next_nibble_bitlength = secret.bitlength + (4 - (secret.bitlength % 4))
        prime_bitlength       = next_nibble_bitlength + 1
        prime                 = OpenSSL::BN.generate_prime(prime_bitlength)

        # FIXME : Why does generate_prime always return 35879 for bitlength 1-15
        # OpenSSL::BN::generate_prime(1).to_i
        # => 35879
        # Do we need to make sure that prime_bitlength is not shorter than 64 bits?
        # See : https://www.mail-archive.com/openssl-dev@openssl.org/msg18835.html
        # See : http://ardoino.com/2005/11/maths-openssl-primes-random/
        # See : http://www.openssl.org/docs/apps/genrsa.html  "Therefore the number of bits should not be less that 64."

        # compute random coefficients
        (1..k - 1).each { |x| coefficients[x] = get_random_number(secret.bitlength) }

        (1..n).each do |x|
          p_x = evaluate_polynomial_at(x, coefficients, prime)
          new_share = new(:x => x, :y => p_x, :prime => prime, :prime_bitlength => prime_bitlength, :k => k, :n => n, :hmac => secret.hmac)
          shares[x - 1] = new_share
        end
        shares
      end

      # Recover the secret by doing Lagrange interpolation.
      def self.recover_secret(shares)
        return false unless shares.length >= shares[0].k

        # All Shares must have the same HMAC or they were derived from different Secrets
        hmacs = shares.map(&:hmac).uniq
        fail ArgumentError, 'Share mismatch. Not all Shares have a common HMAC.' unless hmacs.size == 1

        secret = SecretSharing::Shamir::Secret.new(:secret => OpenSSL::BN.new('0'))

        shares.each do |share|
          l_x = lagrange(share.x, shares)
          summand = share.y * l_x
          summand %= share.prime
          secret.secret += summand
          secret.secret %= share.prime
        end

        if secret && secret.is_a?(SecretSharing::Shamir::Secret) && secret.valid_hmac?
          return secret
        else
          fail ArgumentError, 'Secret recovery failure. The generated Secret does not match the HMACs in the Shares provided.'
        end
      end

      private

      def unpack_share(share)
        decoded  = usafe_decode64(share)
        h        = MultiJson.load(decoded, :symbolize_keys => true)

        @version         = h[:version].to_i                unless h[:version].nil?
        @hmac            = h[:hmac]                        unless h[:hmac].nil?
        @k               = h[:k].to_i                      unless h[:k].nil?
        @n               = h[:n].to_i                      unless h[:n].nil?
        @x               = h[:x].to_i                      unless h[:x].nil?
        @y               = OpenSSL::BN.new(h[:y].to_s)     unless h[:y].nil?
        @prime           = OpenSSL::BN.new(h[:prime].to_s) unless h[:prime].nil?
        @prime_bitlength = h[:prime_bitlength].to_i        unless h[:prime_bitlength].nil?
      end
    end # class Share
  end # module Shamir
end # module SecretSharing
