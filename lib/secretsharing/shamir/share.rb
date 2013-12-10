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
    # A SecretSharing::Shamir::Share object represents a share in the
    # Shamir secret sharing scheme. The share consists of a point (x,y) on
    # a polynomial over Z/Zp, where p is a prime.
    class Share
      include SecretSharing::Shamir
      attr_accessor :share, :x, :y, :prime, :prime_bitlength, :version

      # Create a new share with the given XY point, prime and prime bitlength.
      def initialize(opts = {})
        opts = {
          :share           => nil,
          :x               => nil,
          :y               => nil,
          :prime           => nil,
          :prime_bitlength => nil,
          :version         => 0
        }.merge!(opts)

        # override with options
        opts.each_key do |k|
          if self.respond_to?("#{k}=")
            send("#{k}=", opts[k])
          else
            fail ArgumentError, "Argument '#{k}' is not allowed"
          end
        end

        parse_share if @share.is_a?(String) && !@share.empty?

        if @x.nil? || @y.nil? || @prime.nil? || @prime_bitlength.nil?
          fail ArgumentError, 'A String :share OR :x, :y, :prime, and :prime_bitlength were expected.'
        end
      end

      def to_s
        generate_share
      end

      # Shares are equal if their string representation is the same.
      def ==(other)
        other.to_s == to_s
      end

      private

        def parse_share
          # Create a new share from a string format representation. For
          # a discussion of the format, see the to_s() method.
          @x        = @share[1, 2].hex
          p_x_str   = @share[3, @share.length - 9]
          checksum  = @share[-6, 4]

          begin
            @y = OpenSSL::BN.new(p_x_str, 16)
          rescue StandardError => e
            raise ArgumentError, "Could not initialize OpenSSL::BN with '#{p_x_str}' : #{e.class} : #{e.message}"
          end

          validate_share_version
          validate_checksum(checksum, p_x_str)

          @prime_bitlength = 4 * @share[-2, 2].hex + 1
          @prime = smallest_prime_of_bitlength(@prime_bitlength)
        end

        # A string representation of the share, that can for example be
        # distributed in printed form.
        #
        # The string is an uppercase hexadecimal string of the following
        # format: ABBC*DDDDEEEE, where:
        #
        # * A (the first nibble) is the version number of the format, currently fixed to 0.
        # * B (the next byte, two hex characters) is the x coordinate of the point on the polynomial.
        # * C (the next variable length of bytes) is the y coordinate of the point on the polynomial.
        # * D (the next two bytes, four hex characters) is the two highest
        #   bytes of the SHA1 hash on the string representing the y coordinate,
        #   it is used as a checksum to guard against typos
        # * E (the next two bytes, four hex characters) is the bitlength of the
        #   prime number in nibbles.
        def generate_share
          # bitlength in nibbles to save space
          prime_nibbles = (@prime_bitlength - 1) / 4
          p_x = sprintf('%x', @y).upcase

          share = ''
          share << @version.to_s
          share << sprintf('%02x', @x)
          share << p_x
          share << Digest::SHA1.hexdigest(p_x)[0, 4]
          share << sprintf('%02x', prime_nibbles)
          share.upcase
        end

        def validate_share_version
          version = @share[0, 1]
          fail "Invalid share format version # '#{version}', expected '0'" if version != '0'
        end

        def validate_checksum(checksum, p_x_str)
          computed_checksum = Digest::SHA1.hexdigest(p_x_str)[0, 4].upcase
          if checksum != computed_checksum
            fail "Invalid checksum. Expected #{computed_checksum}, got #{checksum}"
          end
        end
    end # class Share
  end # module Shamir
end # module SecretSharing
