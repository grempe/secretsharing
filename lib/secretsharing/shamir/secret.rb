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
  module Shamir
    # A SecretSharing::Shamir::Secret object represents a Secret in the
    # Shamir secret sharing scheme. Secrets can be passed in as an input
    # argument when creating a new SecretSharing::Shamir::Container or
    # can be the output from a Container that has successfully decoded shares.
    # A new Secret take 0 or 1 args. Zero args means the Secret will be initialized
    # with a random OpenSSL::BN object with the Secret::DEFAULT_BITLENGTH. If a
    # single argument is passed it can be one of two object types, String or
    # OpenSSL::BN.  If a String it is expected to be a specially encoded String
    # that was generated as the output of calling #to_s on another Secret object.
    # If the object type is OpenSSL::BN it can represent a number up to 4096 num_bits
    # in length as reported by OpenSSL::BN#num_bits.
    #
    # All secrets are internally represented as an OpenSSL::BN which can be retrieved
    # in its raw form using #secret.
    #
    class Secret
      include SecretSharing::Shamir

      DEFAULT_BITLENGTH = 256
      MAX_BITLENGTH     = 4096

      attr_reader :bitlength
      attr_accessor :secret

      def initialize(secret = get_random_number(SecretSharing::Shamir::Secret::DEFAULT_BITLENGTH))
        if secret.is_a?(String)
          # Decode a Base64.urlsafe_encode64 String which contains a Base 36 encoded Bignum back into an OpenSSL::BN
          # See : Secret#to_s for forward encoding method.
          decoded_secret = urlsafe_decode64(secret)
          fail ArgumentError, 'invalid base64 (returned nil or empty String)' if decoded_secret.empty?
          secret = OpenSSL::BN.new(decoded_secret.to_i(36).to_s)
        end

        @secret = secret
        fail ArgumentError, 'Secret must be an OpenSSL::BN' unless @secret.is_a?(OpenSSL::BN)
        @bitlength = @secret.num_bits
        fail ArgumentError, "Secret must have a bitlength less than or equal to #{MAX_BITLENGTH}" if @bitlength > MAX_BITLENGTH
      end

      # Secrets are equal if the OpenSSL::BN in @secret is the same.
      def ==(other)
        other == @secret
      end

      def secret?
        @secret.is_a?(OpenSSL::BN)
      end

      def to_s
        # Convert the OpenSSL::BN secret to an Bignum which has a #to_s(36) method
        # Convert the Bignum to a Base 36 encoded String
        # Wrap the Base 36 encoded String as a URL safe Base 64 encoded String
        # Combined this should result in a relatively compact and portable String
        urlsafe_encode64(@secret.to_i.to_s(36))
      end

      private

        # Backported for ruby 1.8.7, REE, jruby
        def urlsafe_decode64(str)
          return Base64.urlsafe_decode64(str) if Base64.respond_to?(:urlsafe_decode64)

          if str.include?('\n')
            fail(ArgumentError, 'invalid base64')
          else
            Base64.decode64(str)
          end
        end

        # Backported for ruby 1.8.7, REE, jruby
        def urlsafe_encode64(bin)
          return Base64.urlsafe_encode64(bin) if Base64.respond_to?(:urlsafe_encode64)
          Base64.encode64(bin).tr("\n", '')
        end
    end # class Secret
  end # module Shamir
end # module SecretSharing
