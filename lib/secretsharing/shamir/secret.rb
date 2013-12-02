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
    class Secret
      attr_accessor :secret

      def initialize(secret = OpenSSL::BN.new('0'))
        @secret = secret
        fail ArgumentError, 'secret must be an OpenSSL::BN' unless @secret.is_a?(OpenSSL::BN)
      end

      # Secrets are equal if the OpenSSL::BN in @secret is the same.
      def ==(other)
        other == secret
      end

      def secret?
        @secret.is_a?(OpenSSL::BN)
      end

      # The secret in a password representation
      def to_base64
        return nil unless secret?
        Base64.encode64([@secret.to_s(16)].pack('h*')).split("\n").join
      end
    end # class Secret
  end # module Shamir
end # module SecretSharing
