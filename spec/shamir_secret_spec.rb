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

    before do
      @num = OpenSSL::BN.new('1234567890')
      @s = SecretSharing::Shamir::Secret.new(:secret => @num, :pbkdf2_iterations => 5)
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

    it 'must respond to #pbkdf2_salt' do
      @s.respond_to?(:pbkdf2_salt).must_equal(true)
    end

    it 'must respond to #pbkdf2_iterations' do
      @s.respond_to?(:pbkdf2_iterations).must_equal(true)
    end

    it 'must respond to #pbkdf2_hash' do
      @s.respond_to?(:pbkdf2_hash).must_equal(true)
    end

    it 'must respond to #pbkdf2_hash_function' do
      @s.respond_to?(:pbkdf2_hash_function).must_equal(true)
    end

    it 'must initialize with a random secret and set @secret and @bitlength by default' do
      @s.secret.is_a?(OpenSSL::BN).must_equal(true)
      @s.bitlength.is_a?(Integer).must_equal(true)
    end

    it 'must raise an ArgumentError if an Integer instead of an OpenSSL::BN is provided to the constructor' do
      lambda { SecretSharing::Shamir::Secret.new(:secret => 1_234_567_890, :pbkdf2_iterations => 5) }.must_raise(ArgumentError)
    end

    it 'must raise an ArgumentError if the bitlength of the secret is greater than MAX_BITLENGTH' do
      # 1234 * 1's is 4097 num_bits
      lambda { SecretSharing::Shamir::Secret.new(:secret => OpenSSL::BN.new("#{'1' * 1234}"), :pbkdf2_iterations => 5) }.must_raise(ArgumentError)
    end

    it 'must initialize with a fixed secret and set @secret and @bitlength to the same if passed an OpenSSL::BN' do
      @s.secret.is_a?(OpenSSL::BN).must_equal(true)
      @s.secret.must_equal(@num)
      @s.bitlength.is_a?(Integer).must_equal(true)
      @s.bitlength.must_equal(@num.num_bits)
    end

    it 'must throw an exception if initialized with a String that does not base64 re-hydrate as expected from the output of #to_s' do
      lambda { SecretSharing::Shamir::Secret.new(:secret => 'foo', :pbkdf2_iterations => 5) }.must_raise(ArgumentError)
    end

    it 'must throw an exception if initialized with a String that contains \n on platform that is not true for Base64.respond_to?(:urlsafe_encode64)' do
      Base64.stub(:respond_to?, false) do
        lambda { SecretSharing::Shamir::Secret.new(:secret => 'foo\nbar', :pbkdf2_iterations => 5) }.must_raise(ArgumentError)
      end
    end

    it 'must use Base64.decode64 instead of Base64.urlsafe_decode64 on platform that is not true for Base64.respond_to?(:urlsafe_encode64)' do
      Base64.stub(:respond_to?, false) do
        num = OpenSSL::BN.new('1234567890123456789012345678901234567890')
        s1 = SecretSharing::Shamir::Secret.new(:secret => num, :pbkdf2_iterations => 5)
        s1_str = s1.to_s
        s1_str.must_equal('MWl6aWJqZjR6dmRibXZxNjZkNndtOGcxY2k=')

        # Re-hydrate a new Secret object from the previously de-hydrated String
        s2 = SecretSharing::Shamir::Secret.new(:secret => s1_str, :pbkdf2_iterations => 5)
        s2.must_equal(s1)
      end
    end

    it 'must decode to the SAME String on mixed platforms that are, or are not, truthy for Base64.respond_to?(:urlsafe_decode64)' do

      # NOTE : OpenSSL::BN.new('1234567890123456789012345678901234567890')
      str = 'MWl6aWJqZjR6dmRibXZxNjZkNndtOGcxY2k='
      s2 = nil
      s3 = nil

      s1 = SecretSharing::Shamir::Secret.new(:secret => str, :pbkdf2_iterations => 5)
      s1_str = s1.to_s
      s1_str.must_equal(str)

      Base64.stub(:respond_to?, false) do
        s2 = SecretSharing::Shamir::Secret.new(:secret => str, :pbkdf2_iterations => 5)
        s2_str = s2.to_s
        s2_str.must_equal(str)
      end

      Base64.stub(:respond_to?, false) do
        s3 = SecretSharing::Shamir::Secret.new(:secret => str, :pbkdf2_iterations => 5)
        s3_str = s3.to_s
        s3_str.must_equal(str)
      end

      s1.must_equal(s2)
      s1.must_equal(s3)
    end

    it 'must initialize with PBKDF2 instance variables appropriately set' do
      s = SecretSharing::Shamir::Secret.new(:secret => @num)
      s.pbkdf2_salt.is_a?(String).must_equal(true)
      s.pbkdf2_iterations.is_a?(Integer).must_equal(true)
      s.pbkdf2_iterations.must_equal(20_000)
      s.pbkdf2_hash_function.is_a?(OpenSSL::Digest::SHA512).must_equal(true)
    end

    it 'must initialize with a PBKDF2 hash based on the @secret' do
      @s.pbkdf2_hash.is_a?(String).must_equal(true)
    end

    it 'must throw an ArgumentError if an unknown option hash key is passed in' do
      lambda { SecretSharing::Shamir::Secret.new(:secret => 'foo\nbar', :pbkdf2_iterations => 5, :unknown_arg => true) }.must_raise(ArgumentError)
    end

  end # describe initialization

  describe '==' do

    before do
      @num = OpenSSL::BN.new('1234567890')
      @s = SecretSharing::Shamir::Secret.new(:secret => @num, :pbkdf2_iterations => 5)
    end

    it 'must return true if two secrets have the same OpenSSL::BN set internally' do
      s2 = @s
      (@s == s2).must_equal(true)
    end

    it 'must return false if two secrets have different OpenSSL::BN set internally' do
      s2 = SecretSharing::Shamir::Secret.new(:secret => OpenSSL::BN.new('987654321'), :pbkdf2_iterations => 5)
      (@s == s2).must_equal(false)
    end
  end

  describe 'secret?' do
    before do
      @num = OpenSSL::BN.new('1234567890')
      @s = SecretSharing::Shamir::Secret.new(:secret => @num, :pbkdf2_iterations => 5)
    end

    it 'must return true if a secret is set' do
      @s.secret.is_a?(OpenSSL::BN).must_equal(true)
      @s.secret?.must_equal(true)
    end

    it 'must return false if a secret is not set' do
      @s.secret = nil
      @s.secret?.must_equal(false)
    end
  end

  describe 'to_s' do
    it 'must return a proper and consistent URL safe encoded String representation of @secret and allow round trip of that String' do
      num = OpenSSL::BN.new('1234567890123456789012345678901234567890')
      s1 = SecretSharing::Shamir::Secret.new(:secret => num, :pbkdf2_iterations => 5)
      s1_str = s1.to_s
      s1_str.must_equal('MWl6aWJqZjR6dmRibXZxNjZkNndtOGcxY2k=')

      # Re-hydrate a new Secret object from the previously de-hydrated String
      s2 = SecretSharing::Shamir::Secret.new(:secret => s1_str, :pbkdf2_iterations => 5)
      s2.must_equal(s1)
    end
  end

  describe 'pbkdf2_hash' do
    before do
      @num = OpenSSL::BN.new('1234567890')
    end

    it 'must return the expected pbkdf2_hash value with a non-random salt' do
      @s = SecretSharing::Shamir::Secret.new(:secret => @num, :pbkdf2_salt => 'badsalt')
      @s.pbkdf2_hash.must_equal('4f5727071b76b0e1ee4f27229bc62cab6cf75c18621cd8b94e71066b7432fa004681d074764d935ece3208225d672cfed372a30af2ea2118bf1e8e1e61b97214')
    end

    it 'must return the different pbkdf2_hash values with default random salt' do
      @s1 = SecretSharing::Shamir::Secret.new(:secret => @num)
      @s2 = SecretSharing::Shamir::Secret.new(:secret => @num)
      (@s1.pbkdf2_hash == @s2.pbkdf2_hash).must_equal(false)
    end
  end
end # describe SecretSharing::Shamir::Secret
