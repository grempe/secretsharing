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

require File.expand_path('../spec_helper', __FILE__)

describe SecretSharing::Shamir::Secret do

  describe 'initialization' do

    it 'must return the correct default secret bitlength constant value' do
      SecretSharing::Shamir::Secret::DEFAULT_BITLENGTH.must_equal(256)
    end

    it 'must return the correct max secret bitlength constant value' do
      SecretSharing::Shamir::Secret::MAX_BITLENGTH.must_equal(4096)
    end

    it 'must respond to #secret' do
      s = SecretSharing::Shamir::Secret.new
      s.respond_to?(:secret).must_equal(true)
    end

    it 'must respond to #bitlength' do
      s = SecretSharing::Shamir::Secret.new
      s.respond_to?(:bitlength).must_equal(true)
    end

    it 'must initialize with a random secret and set @secret and @bitlength by default' do
      s = SecretSharing::Shamir::Secret.new
      s.secret.is_a?(OpenSSL::BN).must_equal(true)
      s.bitlength.is_a?(Integer).must_equal(true)
    end

    it 'must raise an ArgumentError if a String instead of an OpenSSL::BN is provided to the constructor' do
      lambda { SecretSharing::Shamir::Secret.new('foo') }.must_raise(ArgumentError)
    end

    it 'must raise an ArgumentError if an Integer instead of an OpenSSL::BN is provided to the constructor' do
      lambda { SecretSharing::Shamir::Secret.new(1_234_567_890) }.must_raise(ArgumentError)
    end

    it 'must raise an ArgumentError if the bitlength of the secret is greater than MAX_BITLENGTH' do
      # 1234 * 1's is 4097 num_bits
      lambda { SecretSharing::Shamir::Secret.new(OpenSSL::BN.new("#{'1' * 1234}")) }.must_raise(ArgumentError)
    end

    it 'must initialize with a fixed secret and set @secret and @bitlength to the same if passed an OpenSSL::BN' do
      num = OpenSSL::BN.new('1234567890')
      s = SecretSharing::Shamir::Secret.new(num)
      s.secret.is_a?(OpenSSL::BN).must_equal(true)
      s.secret.must_equal(num)
      s.bitlength.is_a?(Integer).must_equal(true)
      s.bitlength.must_equal(num.num_bits)
    end
  end # describe initialization

  describe '==' do
    it 'must return true if two secrets have the same OpenSSL::BN set internally' do
      num = OpenSSL::BN.new('1234567890')
      s1 = SecretSharing::Shamir::Secret.new(num)
      s2 = SecretSharing::Shamir::Secret.new(num)
      (s1 == s2).must_equal(true)
    end

    it 'must return false if two secrets have different OpenSSL::BN set internally' do
      num1 = OpenSSL::BN.new('123456789')
      num2 = OpenSSL::BN.new('987654321')
      s1 = SecretSharing::Shamir::Secret.new(num1)
      s2 = SecretSharing::Shamir::Secret.new(num2)
      (s1 == s2).must_equal(false)
    end
  end

  describe 'secret?' do
    it 'must return true if a secret is set' do
      s = SecretSharing::Shamir::Secret.new
      s.secret.is_a?(OpenSSL::BN).must_equal(true)
      s.secret?.must_equal(true)
    end
  end

  describe 'to_base64' do
    it 'must return a proper and consistent base64 encoded String representation of @secret' do
      num = OpenSSL::BN.new('1234567890123456789012345678901234567890')
      s = SecretSharing::Shamir::Secret.new(num)
      s.to_base64.must_equal('MAqcAlcMvT+Lysv1aezzoC0=')
    end
  end

  describe 'to_s' do
    it 'must return a proper and consistent String representation of @secret' do
      num = OpenSSL::BN.new('1234567890123456789012345678901234567890')
      s = SecretSharing::Shamir::Secret.new(num)
      s.to_s.must_equal(num.to_s)
    end
  end
end # describe SecretSharing::Shamir::Secret
