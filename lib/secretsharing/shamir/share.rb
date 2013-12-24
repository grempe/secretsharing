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
          :prime_bitlength => nil,
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
