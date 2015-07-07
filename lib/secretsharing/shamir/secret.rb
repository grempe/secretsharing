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
  module Shamir
    # A SecretSharing::Shamir::Secret object represents a Secret in the
    # Shamir secret sharing scheme. Secrets can be passed in as an input
    # argument when creating a new SecretSharing::Shamir::Container or
    # can be the output from a Container that has successfully decoded shares.
    # A new Secret take 0 or 1 args. Zero args means the Secret will be initialized
    # with a random Numeric object with the Secret::DEFAULT_BITLENGTH. If a
    # single argument is passed it can be a String, or Integer.
    # If its a String, its expected to be of a special encoding
    # that was generated as the output of calling #to_s on another Secret object.
    # If the object type is an Integer it can be up to 4096 bits in length.
    #
    # All secrets are internally represented as a Numeric which can be retrieved
    # in its raw form using #secret.
    #
    class Secret
      include SecretSharing::Shamir

      # FIXME : Is a MAX_BITLENGTH really needed?  Can it be larger if so?

      MAX_BITLENGTH = 4096

      attr_accessor :secret, :bitlength, :hmac

      # FIXME : allow instantiating a secret with any random number bitlength you choose.

      def initialize(opts = {})
        opts = {
          :secret => get_random_number(32) # Bytes
        }.merge!(opts)

        # override with options
        opts.each_key do |k|
          if self.respond_to?("#{k}=")
            send("#{k}=", opts[k])
          else
            fail ArgumentError, "Argument '#{k}' is not allowed"
          end
        end

        # FIXME : Do we really need the ability for a String arg to re-instantiate a Secret?
        # FIXME : If its a String, shouldn't it be able to be an arbitrary String converted to/from a Number?

        if opts[:secret].is_a?(String)
          # Decode a Base64.urlsafe_encode64 String which contains a Base 36 encoded Bignum back into a Bignum
          # See : Secret#to_s for forward encoding method.
          decoded_secret = usafe_decode64(opts[:secret])
          fail ArgumentError, 'invalid base64 (returned nil or empty String)' if decoded_secret.empty?
          @secret = decoded_secret.to_i(36)
        end

        @secret = opts[:secret] if @secret.nil?
        fail ArgumentError, "Secret must be an Integer, not a '#{@secret.class}'" unless @secret.is_a?(Integer)

        # Get the number of binary bits in this secret's value.
        @bitlength = @secret.bit_length

        fail ArgumentError, "Secret must have a bitlength less than or equal to #{MAX_BITLENGTH}" if @bitlength > MAX_BITLENGTH

        generate_hmac
      end

      # Secrets are equal if the Numeric in @secret is the same.
      # Do secure constant-time comparison of the objects.
      def ==(other)
        other_secret_hash = RbNaCl::Hash.blake2b(other.secret.to_s, digest_size: 32)
        own_secret_hash   = RbNaCl::Hash.blake2b(@secret.to_s, digest_size: 32)
        RbNaCl::Util.verify32(other_secret_hash, own_secret_hash)
      end

      # Set a new secret forces regeneration of the HMAC
      def secret=(secret)
        @secret = secret
        generate_hmac
      end

      def secret?
        @secret.is_a?(Integer)
      end

      def to_s
        # Convert the Bignum to a Base 36 encoded String
        # Wrap the Base 36 encoded String as a URL safe Base 64 encoded String
        # Combined this should result in a relatively compact and portable String
        usafe_encode64(@secret.to_s(36))
      end

      # See : generate_hmac
      def valid_hmac?
        return false if !@secret.is_a?(Integer) || @hmac.to_s.empty? || @secret.to_s.empty?
        hash = RbNaCl::Hash.sha512(@secret.to_s)
        key = hash[0, 32]
        authenticator = RbNaCl::Util.hex2bin(@hmac)
        msg = hash[33, 64]
        begin
          RbNaCl::HMAC::SHA256.verify(key, authenticator, msg)
        rescue
          false
        end
      end

      private

      # SHA512 over @secret returns a 64 Byte array. Use the first 32 bytes
      # as the HMAC key, and the last 32 bytes as the message.
      #
      # This will allow a point of comparison between the original secret that
      # was split into shares, and the secret that was retrieved by combining shares.
      def generate_hmac
        return false if @secret.to_s.empty?
        hash = RbNaCl::Hash.sha512(@secret.to_s)
        key = hash[0, 32]
        msg = hash[33, 64]
        @hmac = RbNaCl::Util.bin2hex(RbNaCl::HMAC::SHA256.auth(key, msg))
      end
    end # class Secret
  end # module Shamir
end # module SecretSharing
