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

require File.expand_path('../spec_helper', __FILE__)

describe SecretSharing::Shamir::Secret do
  describe 'initialization with OpenSSL::BN' do
    before do
      @num = OpenSSL::BN.new('1234567890')
      @s = SecretSharing::Shamir::Secret.new(:secret => @num)
    end

    it 'must initialize with a random secret and set @secret and @bitlength by default' do
      @s.secret.is_a?(Integer).must_equal(true)
      @s.bitlength.is_a?(Integer).must_equal(true)
    end
  end # describe initialization with OpenSSL::BN

  describe 'initialization with Integer' do
    before do
      @num = 12345
      @s = SecretSharing::Shamir::Secret.new(:secret => @num)
    end

    it 'must initialize with a random secret and set @secret and @bitlength by default' do
      @s.secret.is_a?(Integer).must_equal(true)
      @s.bitlength.is_a?(Integer).must_equal(true)
    end
  end # describe initialization with Integer

  describe 'initialization with Bignum' do
    before do
      @num = 12345678909123098902183908908213829013
      @s = SecretSharing::Shamir::Secret.new(:secret => @num)
    end

    it 'must return the correct max secret bitlength constant value' do
      SecretSharing::Shamir::Secret::MAX_BITLENGTH.must_equal(4096)
    end

    it 'must respond to #secret' do
      @s.respond_to?(:secret).must_equal(true)
    end

    it 'must respond to #bitlength' do
      @s.respond_to?(:bitlength).must_equal(true)
    end

    it 'must respond to #valid_hmac?' do
      @s.respond_to?(:valid_hmac?).must_equal(true)
    end

    it 'must initialize with a random secret and set @secret and @bitlength by default' do
      @s.secret.is_a?(Integer).must_equal(true)
      @s.bitlength.is_a?(Integer).must_equal(true)
    end

    it 'must raise an ArgumentError if the bitlength of the secret is greater than MAX_BITLENGTH' do
      # 1234 * 1's is 4097 num_bits
      lambda { SecretSharing::Shamir::Secret.new(:secret => '1' * 1234) }.must_raise(ArgumentError)
    end

    it 'must initialize with a fixed secret and set @secret and @bitlength to the same if passed a Bignum' do
      @s.secret.is_a?(Integer).must_equal(true)
      @s.secret.must_equal(@num)
      @s.bitlength.is_a?(Integer).must_equal(true)
      @s.bitlength.must_equal(@num.bit_length)
    end

    it 'must throw an exception if initialized with a String that does not base64 re-hydrate as expected from the output of #to_s' do
      lambda { SecretSharing::Shamir::Secret.new(:secret => 'foo') }.must_raise(ArgumentError)
    end

    it 'must throw an exception if initialized with a String that contains \n on platform that is not true for Base64.respond_to?(:urlsafe_encode64)' do
      Base64.stub(:respond_to?, false) do
        lambda { SecretSharing::Shamir::Secret.new(:secret => 'foo\nbar') }.must_raise(ArgumentError)
      end
    end

    it 'must use Base64.decode64 instead of Base64.urlsafe_decode64 on platform that is not true for Base64.respond_to?(:urlsafe_encode64)' do
      Base64.stub(:respond_to?, false) do
        num = 1234567890123456789012345678901234567890
        s1 = SecretSharing::Shamir::Secret.new(:secret => num)
        s1_str = s1.to_s
        s1_str.must_equal('MWl6aWJqZjR6dmRibXZxNjZkNndtOGcxY2k=')

        # Re-hydrate a new Secret object from the previously de-hydrated String
        s2 = SecretSharing::Shamir::Secret.new(:secret => s1_str)
        s2.must_equal(s1)
      end
    end

    it 'must decode to the SAME String on mixed platforms that are, or are not, truthy for Base64.respond_to?(:urlsafe_decode64)' do
      # NOTE : 1234567890123456789012345678901234567890
      str = 'MWl6aWJqZjR6dmRibXZxNjZkNndtOGcxY2k='
      s2 = nil
      s3 = nil

      s1 = SecretSharing::Shamir::Secret.new(:secret => str)
      s1_str = s1.to_s
      s1_str.must_equal(str)

      Base64.stub(:respond_to?, false) do
        s2 = SecretSharing::Shamir::Secret.new(:secret => str)
        s2_str = s2.to_s
        s2_str.must_equal(str)
      end

      Base64.stub(:respond_to?, false) do
        s3 = SecretSharing::Shamir::Secret.new(:secret => str)
        s3_str = s3.to_s
        s3_str.must_equal(str)
      end

      s1.must_equal(s2)
      s1.must_equal(s3)
    end

    it 'must throw an ArgumentError if an unknown option hash key is passed in' do
      lambda { SecretSharing::Shamir::Secret.new(:secret => 'foo\nbar', :unknown_arg => true) }.must_raise(ArgumentError)
    end
  end # describe initialization

  describe '==' do
    before do
      @num = 1234567890
      @s = SecretSharing::Shamir::Secret.new(:secret => @num)
    end

    it 'must return true if two secrets have the same Integer set internally' do
      s2 = @s
      (@s == s2).must_equal(true)
    end

    it 'must return false if two secrets have different Integers set internally' do
      s2 = SecretSharing::Shamir::Secret.new(:secret => 987654321)
      (@s == s2).must_equal(false)
    end
  end

  describe 'secret?' do
    before do
      @num = 1234567890
      @s = SecretSharing::Shamir::Secret.new(:secret => @num)
    end

    it 'must return true if a secret is set' do
      @s.secret.is_a?(Integer).must_equal(true)
      @s.secret?.must_equal(true)
    end

    it 'must return false if a secret is not set' do
      @s.secret = nil
      @s.secret?.must_equal(false)
    end
  end

  describe 'secret()' do
    before do
      @num = 1234567890
      @s = SecretSharing::Shamir::Secret.new(:secret => @num)
    end

    it 'must return true if a secret is set' do
      @s.secret.is_a?(Integer).must_equal(true)
      @s.secret?.must_equal(true)
    end

    it 'must return false if a secret is not set' do
      @s.secret = nil
      @s.secret?.must_equal(false)
    end
  end

  describe 'to_s' do
    it 'must return a proper and consistent URL safe encoded String representation of @secret and allow round trip of that String' do
      num = 1234567890123456789012345678901234567890
      s1 = SecretSharing::Shamir::Secret.new(:secret => num)
      s1_str = s1.to_s
      s1_str.must_equal('MWl6aWJqZjR6dmRibXZxNjZkNndtOGcxY2k=')

      # Re-hydrate a new Secret object from the previously de-hydrated String
      s2 = SecretSharing::Shamir::Secret.new(:secret => s1_str)
      s2.must_equal(s1)
    end
  end

  describe 'valid_hmac?' do
    before do
      @num = 1234567890
      @s = SecretSharing::Shamir::Secret.new(:secret => @num)
    end

    it 'must return true if a a valid HMAC based on the secret is set' do
      @s.valid_hmac?.must_equal(true)
    end

    it 'must return false if a secret is not set' do
      @s.secret = nil
      @s.valid_hmac?.must_equal(false)
    end

    it 'must return false if the HMAC was tampered with at all' do
      @s.hmac = @s.hmac + 'a'
      @s.valid_hmac?.must_equal(false)
    end
  end
end # describe SecretSharing::Shamir::Secret
